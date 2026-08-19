// Pre-instantiation bounds on a module's declared linear memory (README §4.3), plus the
// shared §12.3 guest-realm bounds and the §4.1 scratch default every host's table must
// agree on.
//
// Memory cannot be bounded *after* instantiation: `new WebAssembly.Instance` allocates the
// declared initial memory before any export runs, so a module declaring 4 GiB has already
// taken the host down by the time module-table.ts sees it. The bound has to be read off
// the bytes first, which is what this file is for. (Compute is bounded at each target's
// engine instead — module-table.ts's worker kill, wazero's `WithCloseOnContextDone`.)
//
// The JS WebAssembly API exposes no memory limits on a compiled `Module`, so this walks
// the binary's section headers. It is a *bounds read*, not a validator — the engine still
// validates at compile time — and anything it cannot parse is refused, because a module
// whose sections do not parse is one whose footprint cannot be bounded either.
//
// Two refusals are structural rather than budgetary: an IMPORTED memory would be
// host-supplied, the one way a pure transform could reach bytes it did not declare (§4.2),
// and a SHARED one would be visible to another agent (§4.3).

/** WebAssembly linear-memory page size. Limits are declared in pages, budgets in bytes. */
export const WASM_PAGE_BYTES = 65536;

/** The I/O region a module reserves at its `scratch` export when it declares no
 *  `scratchSize` (§4.1). One number on every target: a payload the JS table admits and the
 *  Go one refuses is a module that loads on one node and not another. The Go side receives
 *  it from the shared shim at every slot build. */
export const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

/** Default heap cap for a confined guest realm (§12.3). Deliberately equal to
 *  `DEFAULT_MAX_MODULE_MEMORY_BYTES` below, so the two kinds of untrusted code a bundle can
 *  ship are held to one number rather than two that drift. */
export const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default budget of guest execution time per entrypoint invocation (§12.3). Generous for
 *  any real request, and short enough that a wedged guest frees the host thread. */
export const DEFAULT_GUEST_DEADLINE_MS = 5000;

/** How many deadlines one guest realm may hold at once (§12.3). A guest cannot create a
 *  timer for itself, so every live one is an entry in a host-side table and an unbounded
 *  `timer/arm` loop would spend the host's memory rather than the guest's heap. Per realm,
 *  because the shell wires one timer table per realm. */
export const DEFAULT_MAX_LIVE_TIMERS = 1 << 16;

/** Default ceiling on a module's declared linear memory. Declared here rather than in a
 *  host because `loadBundleModules` applies it on the shared admission path (§3): a host
 *  may hold its own direct builds to something tighter, but none may be looser about what
 *  a *bundle* may land. */
export const DEFAULT_MAX_MODULE_MEMORY_BYTES = 64 * 1024 * 1024; // 64 MiB

export interface MemoryLimits {
  /** Initial size in pages — allocated eagerly at instantiation, so this is the
   *  number that decides whether instantiating the module is itself an attack. */
  initialPages: number;
  /** Declared maximum in pages, or null when the module declares none. A module with
   *  no maximum may `memory.grow` up to whatever the engine allows, so the host cannot
   *  bound it and refuses it (see `checkModuleMemory`). */
  maxPages: number | null;
}

interface Cursor { readonly b: Uint8Array; i: number; }

/** LEB128 u32. Accumulated by multiplication rather than `<<`, which is 32-bit *signed*
 *  in JS and would turn a legitimate 5-byte length into a negative number. */
function readVarU32(c: Cursor): number {
  let result = 0;
  let shift = 0;
  for (let n = 0; n < 5; n++) {
    if (c.i >= c.b.length) throw new Error("wasm: truncated LEB128");
    const byte = c.b[c.i++];
    result += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return result;
    shift += 7;
  }
  throw new Error("wasm: LEB128 too long for a u32");
}

function skipName(c: Cursor): void {
  const len = readVarU32(c);
  c.i += len;
  if (c.i > c.b.length) throw new Error("wasm: truncated name");
}

/** A `limits` record: a flags byte, then the initial size, then the maximum if declared.
 *  Flags above 0x01 mean shared memory (0x02/0x03) or a 64-bit index type (0x04+), both
 *  outside the §4 pure-transform contract — refused by name so the message says why. */
function readLimits(c: Cursor): MemoryLimits {
  if (c.i >= c.b.length) throw new Error("wasm: truncated limits");
  const flags = c.b[c.i++];
  if (flags & 0x02) throw new Error("wasm: module declares a shared memory — refused (§4.3: a module's memory is private to it)");
  if (flags & ~0x01) throw new Error(`wasm: unsupported memory limits flags 0x${flags.toString(16)}`);
  const initialPages = readVarU32(c);
  const maxPages = (flags & 0x01) ? readVarU32(c) : null;
  return { initialPages, maxPages };
}

/** Read the declared limits of a module's own linear memory, or null when it declares
 *  none. Throws when the module imports a memory, declares more than one, or cannot be
 *  walked. A null return is not a pass — it means the module exports no memory of its
 *  own, which module-table's `memory` export check then refuses with its own message. */
export function readMemoryLimits(wasm: Uint8Array): MemoryLimits | null {
  if (wasm.length < 8) throw new Error("wasm: too short to be a module");
  if (!(wasm[0] === 0x00 && wasm[1] === 0x61 && wasm[2] === 0x73 && wasm[3] === 0x6d)) {
    throw new Error("wasm: bad magic (not a WebAssembly module)");
  }
  const c: Cursor = { b: wasm, i: 8 };
  let limits: MemoryLimits | null = null;
  while (c.i < wasm.length) {
    const id = wasm[c.i++];
    const size = readVarU32(c);
    const end = c.i + size;
    if (end > wasm.length) throw new Error("wasm: truncated section");
    if (id === 2) {
      // Import section. A module imports nothing from the runtime but its own language
      // runtime's shims, which are functions (§4.2); an imported memory would hand a pure
      // transform bytes it did not declare, so it is refused rather than counted.
      const count = readVarU32(c);
      for (let k = 0; k < count; k++) {
        skipName(c);
        skipName(c);
        if (c.i >= c.b.length) throw new Error("wasm: truncated import");
        const kind = wasm[c.i++];
        if (kind === 0x00) readVarU32(c);                     // func: typeidx
        else if (kind === 0x01) { c.i++; readLimits(c); }     // table: reftype ‖ limits
        else if (kind === 0x02) throw new Error("wasm: module imports a memory — refused (§4.2: a module imports nothing from the runtime)");
        else if (kind === 0x03) c.i += 2;                     // global: valtype ‖ mut
        else throw new Error(`wasm: unknown import kind 0x${kind.toString(16)}`);
      }
    } else if (id === 5) {
      // Memory section.
      const count = readVarU32(c);
      if (count !== 1) throw new Error(`wasm: ${count} memories declared — a module declares exactly one (§4.1)`);
      limits = readLimits(c);
    }
    // Sections this does not read are skipped wholesale; so is any tail left inside one
    // it does, so a future field appended to a section cannot desynchronise the walk.
    c.i = end;
  }
  return limits;
}

/** Refuse a module whose declared memory does not fit `maxBytes` (README §4.3).
 *
 *  The two halves fail for different reasons. `initialPages` is allocated at
 *  instantiation, so an oversized one lands the moment the module is compiled. `maxPages`
 *  bounds `memory.grow` afterwards, and a module declaring NO maximum is refused outright:
 *  WebAssembly gives the embedder no way to impose one after the fact, so an undeclared
 *  maximum is an unbounded one. The cost of the rule is one build flag (AssemblyScript's
 *  `--maximumMemory`).
 *
 *  Returns the limits it validated, or null when the module declares no memory of its own —
 *  which the `memory` export check refuses separately. */
export function checkModuleMemory(wasm: Uint8Array, maxBytes: number): MemoryLimits | null {
  const limits = readMemoryLimits(wasm);
  if (!limits) return null;
  const budgetPages = Math.floor(maxBytes / WASM_PAGE_BYTES);
  if (limits.initialPages > budgetPages) {
    throw new Error(
      `wasm: module declares ${limits.initialPages} initial memory pages, above the host budget of ${budgetPages}`,
    );
  }
  if (limits.maxPages === null) {
    throw new Error(
      "wasm: module declares no memory maximum — refused, since an embedder cannot impose one after instantiation (build with AssemblyScript's --maximumMemory)",
    );
  }
  if (limits.maxPages > budgetPages) {
    throw new Error(
      `wasm: module declares a maximum of ${limits.maxPages} memory pages, above the host budget of ${budgetPages}`,
    );
  }
  return limits;
}
