// Kernel WASM module (README §3). Parses envelopes, dispatches by name.
// No cryptography, no authorization, no installation logic — those live in
// modules.
//
// Exports:
//   alloc, dealloc                — host writes bytes into kernel memory
//   set_handler                   — host-level handler install/replace (§3.1)
//   remove_handler                — SetHandler(name, null) — remove (§3.1)
//   is_registered                 — query handler table
//   dispatch                      — parse envelope + dispatch
//
// Imports:
//   invoke_handler                — called when a handler matches

import { MAGIC, CURRENT_VERSION, MAX_ENVELOPE_BYTES } from "./envelope";

@external("env", "invoke_handler")
declare function invokeHandler(
  handlerId: i32,
  namePtr: i32,
  nameLen: i32,
  payloadPtr: i32,
  payloadLen: i32
): void;

class Entry {
  name: Uint8Array;
  handlerId: i32;
  constructor(name: Uint8Array, handlerId: i32) {
    this.name = name;
    this.handlerId = handlerId;
  }
}

const handlers: Entry[] = [];

// Linear scan over a small handler table. A hashmap keyed by hex(name) was
// tried (M5 in the security review) and proved slower at the table sizes we
// actually run with: building the hex key allocated more than the bytewise
// compare costs to scan ~10 entries. Revisit if N grows past several dozen.
function findIndex(name: Uint8Array): i32 {
  for (let i = 0; i < handlers.length; i++) {
    if (handlers[i].name.length == name.length) {
      let eq = true;
      const n = handlers[i].name;
      for (let j = 0; j < n.length; j++) {
        if (n[j] != name[j]) { eq = false; break; }
      }
      if (eq) return i;
    }
  }
  return -1;
}

/** Zero-copy variant of findIndex that compares the stored name against raw
 *  bytes at `namePtr`. Used by `dispatch` so the hot path doesn't have to
 *  allocate a Uint8Array for every inbound envelope. */
function findIndexAtPtr(namePtr: i32, nameLen: i32): i32 {
  for (let i = 0; i < handlers.length; i++) {
    const n = handlers[i].name;
    if (n.length == nameLen) {
      let eq = true;
      for (let j = 0; j < nameLen; j++) {
        if (n[j] != load<u8>(namePtr + j)) { eq = false; break; }
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
 *  handler for the given name. The kernel never holds two entries for the
 *  same name; replace is in-place. SetHandler is the only way handlers enter
 *  the kernel's table — install records and the capability index live in the
 *  installer above the kernel (§7). */
export function set_handler(
  namePtr: i32,
  nameLen: i32,
  handlerId: i32
): void {
  const name = readBytes(namePtr, nameLen);
  const idx = findIndex(name);
  if (idx >= 0) {
    handlers[idx].handlerId = handlerId;
    return;
  }
  handlers.push(new Entry(name, handlerId));
}

/** SetHandler(name, null) — remove a handler (README §3.1). The host owns
 *  access control. */
export function remove_handler(
  namePtr: i32,
  nameLen: i32
): i32 {
  const name = readBytes(namePtr, nameLen);
  const idx = findIndex(name);
  if (idx < 0) return 0;
  handlers.splice(idx, 1);
  return 1;
}

export function is_registered(namePtr: i32, nameLen: i32): i32 {
  const name = readBytes(namePtr, nameLen);
  return findIndex(name) >= 0 ? 1 : 0;
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

  const nameLen = load<u8>(bytesPtr + 3) as i32;
  if (nameLen == 0) return; // zero-length name is reserved/invalid (§2)
  if (4 + nameLen > bytesLen) return;

  const namePtr = bytesPtr + 4;
  const payloadPtr = namePtr + nameLen;
  const payloadLen = bytesLen - 4 - nameLen;

  const idx = findIndexAtPtr(namePtr, nameLen);
  if (idx < 0) return;

  invokeHandler(
    handlers[idx].handlerId,
    namePtr,
    nameLen,
    payloadPtr,
    payloadLen
  );
}
