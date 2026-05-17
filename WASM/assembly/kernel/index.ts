// Kernel WASM module (README §3). Parses envelopes, dispatches by schema_id.
// No cryptography, no trust, no installation logic — those live in modules.
//
// Exports:
//   alloc, dealloc                — host writes bytes into kernel memory
//   set_handler                   — host-level handler install/replace (§3.1)
//   remove_handler                — SetHandler(schemaId, null) — remove a handler (§3.1)
//   is_registered                 — query handler table
//   handler_count                 — number of registered handlers
//   dispatch                      — parse envelope + dispatch
//
// Imports:
//   invoke_handler                — called when a handler matches

import { MAGIC, CURRENT_VERSION, MAX_ENVELOPE_BYTES } from "./envelope";

@external("env", "invoke_handler")
declare function invokeHandler(
  handlerId: i32,
  schemaPtr: i32,
  schemaLen: i32,
  payloadPtr: i32,
  payloadLen: i32
): void;

class Entry {
  schemaId: Uint8Array;
  handlerId: i32;
  constructor(schemaId: Uint8Array, handlerId: i32) {
    this.schemaId = schemaId;
    this.handlerId = handlerId;
  }
}

const handlers: Entry[] = [];

// Linear scan over a small handler table. A hashmap keyed by hex(schemaId)
// was tried (M5 in the security review) and proved slower at the table sizes
// we actually run with: building the hex key allocated more than the bytewise
// compare costs to scan ~10 entries. Revisit if N grows past several dozen.
function findIndex(schemaId: Uint8Array): i32 {
  for (let i = 0; i < handlers.length; i++) {
    if (handlers[i].schemaId.length == schemaId.length) {
      let eq = true;
      const sid = handlers[i].schemaId;
      for (let j = 0; j < sid.length; j++) {
        if (sid[j] != schemaId[j]) { eq = false; break; }
      }
      if (eq) return i;
    }
  }
  return -1;
}

/** Zero-copy variant of findIndex that compares the stored schema_id against
 *  raw bytes at `schemaPtr`. Used by `dispatch` so the hot path doesn't have
 *  to allocate a Uint8Array for every inbound envelope. */
function findIndexAtPtr(schemaPtr: i32, schemaLen: i32): i32 {
  for (let i = 0; i < handlers.length; i++) {
    const sid = handlers[i].schemaId;
    if (sid.length == schemaLen) {
      let eq = true;
      for (let j = 0; j < schemaLen; j++) {
        if (sid[j] != load<u8>(schemaPtr + j)) { eq = false; break; }
      }
      if (eq) return i;
    }
  }
  return -1;
}

function readBytes(ptr: i32, len: i32): Uint8Array {
  const out = new Uint8Array(len);
  memory.copy(out.dataStart, ptr, len);
  return out;
}

export function alloc(size: i32): i32 {
  return heap.alloc(size) as i32;
}

export function dealloc(ptr: i32): void {
  heap.free(ptr);
}

/** Host-level handler management (README §3.1). Installs or replaces the
 *  handler for the given schema_id. The kernel never holds two entries for
 *  the same schema_id; replace is in-place. SetHandler is the only way
 *  handlers enter the kernel's table — installer attribution and the
 *  capability index live in modules above the kernel. */
export function set_handler(
  schemaPtr: i32,
  schemaLen: i32,
  handlerId: i32
): void {
  const schemaId = readBytes(schemaPtr, schemaLen);
  const idx = findIndex(schemaId);
  if (idx >= 0) {
    handlers[idx].handlerId = handlerId;
    return;
  }
  handlers.push(new Entry(schemaId, handlerId));
}

/** SetHandler(schemaId, null) — remove a handler (README §3.1). The host owns
 *  access control. */
export function remove_handler(
  schemaPtr: i32,
  schemaLen: i32
): i32 {
  const schemaId = readBytes(schemaPtr, schemaLen);
  const idx = findIndex(schemaId);
  if (idx < 0) return 0;
  handlers.splice(idx, 1);
  return 1;
}

export function is_registered(schemaPtr: i32, schemaLen: i32): i32 {
  const schemaId = readBytes(schemaPtr, schemaLen);
  return findIndex(schemaId) >= 0 ? 1 : 0;
}

export function handler_count(): i32 {
  return handlers.length;
}

export function dispatch(bytesPtr: i32, bytesLen: i32): void {
  if (bytesLen > MAX_ENVELOPE_BYTES) return;
  // Zero-copy envelope parsing: read directly from the host-staged buffer at
  // bytesPtr. The buffer is stable for the duration of this call (the host
  // dealloc's only after dispatch returns), so we can pass pointers into it
  // straight through to invoke_handler without making a kernel-side copy.
  if (bytesLen < 4) return;

  const magic: u16 = ((load<u8>(bytesPtr) as u16) << 8) | (load<u8>(bytesPtr + 1) as u16);
  if (magic != MAGIC) return;

  const version = load<u8>(bytesPtr + 2);
  if (version != CURRENT_VERSION) return;

  const schemaLen = load<u8>(bytesPtr + 3) as i32;
  if (schemaLen == 0) return; // zero-length schema_id is reserved/invalid (§2)
  if (4 + schemaLen > bytesLen) return;

  const schemaPtr = bytesPtr + 4;
  const payloadPtr = schemaPtr + schemaLen;
  const payloadLen = bytesLen - 4 - schemaLen;

  const idx = findIndexAtPtr(schemaPtr, schemaLen);
  if (idx < 0) return;

  invokeHandler(
    handlers[idx].handlerId,
    schemaPtr,
    schemaLen,
    payloadPtr,
    payloadLen
  );
}
