// Kernel WASM module (README §3). A named table of handlers: bind a name to a
// handler id, resolve a name to its id. No cryptography, no authorization, no
// installation logic, no message dispatch — the host is the orchestrator and
// invokes handlers by id itself. Handlers are pure transforms (README §4).
//
// Exports:
//   alloc, dealloc                — host writes name bytes into kernel memory
//   set_handler                   — bind / replace a name → handler id (§3.1)
//   remove_handler                — SetHandler(name, null) — unbind (§3.1)
//   find_handler                  — resolve name → handler id, -1 if unbound

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
 *  bytes at `namePtr`. Used by `find_handler` so a lookup doesn't have to
 *  allocate a Uint8Array. */
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

/** Host-level handler management (README §3.1). Binds or replaces the handler for
 *  the given name. The kernel never holds two entries for the same name; replace
 *  is in-place. This is the only way handlers enter the table — install records
 *  and the policy live in the installer above the kernel (§7). */
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

/** Resolve the handler id bound to `name`, or -1 if none is (README §3.1). The
 *  kernel's single routing decision — the host stages the name and reads back the
 *  id, then invokes the handler itself. Zero-copy scan over the raw name bytes. */
export function find_handler(namePtr: i32, nameLen: i32): i32 {
  const idx = findIndexAtPtr(namePtr, nameLen);
  return idx < 0 ? -1 : handlers[idx].handlerId;
}
