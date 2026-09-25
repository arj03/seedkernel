// Module memory bounds, read off the bytes before instantiation (§4.3). Linear memory and
// tables are both charged; an imported or shared one of either is refused. Compute is
// bounded at each target's engine.

/** WebAssembly linear-memory page size. Limits are declared in pages, budgets in bytes. */
export const WASM_PAGE_BYTES = 65536;

/** Host bytes charged per table element (§4.3), against the same budget as linear memory.
 *  Measured ~28 bytes per funcref on V8 and 8 in wazero; one conservative number for
 *  every target. */
export const WASM_TABLE_ELEMENT_BYTES = 32;

/** The `scratch` I/O region when a module declares no `scratchSize` (§4.1). One number on
 *  every target, or a module would load on one node and not another; Go receives it from
 *  the shim. */
export const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

/** Default heap cap for a guest realm (§12.3); equal to `DEFAULT_MAX_MODULE_MEMORY_BYTES`
 *  on purpose. */
export const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default budget per entrypoint invocation (§12.3): guest execution and the wall clock of
 *  every handoff it makes (queue wait, parked host calls, a deferred answer). */
export const DEFAULT_GUEST_DEADLINE_MS = 5000;


/** Unresolved `host.call`s one realm may hold. Each retains host-side state outside the
 *  guest heap, so fire-and-forget calls need a count bound as well as the byte bound below. */
export const DEFAULT_MAX_OUTSTANDING_HOST_CALLS = 1 << 8;

/** Copied input bytes retained by one realm's unresolved `host.call`s, so a stalled
 *  destination cannot turn a confined heap into unbounded host memory. */
export const DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES = 16 * 1024 * 1024;

/** Realms one node may hold. Every per-realm ceiling is multiplied by it, which makes the
 *  node total a ceiling (measured in tests/verify-hardening.mjs, §12.3). Per-realm quotas
 *  rather than a shared pool, so no app can refuse another's calls by being busy. */
export const DEFAULT_MAX_APP_SLOTS = 8;

/** One realm's clock share for work it starts itself (timer roots, §12.3), which could
 *  otherwise re-arm forever. Twice the slot count holds all such roots to half a CPU in
 *  steady state. Peer- and host-started work is not paced by it. */
export const SELF_INITIATED_CLOCK_DIVISOR = 2 * DEFAULT_MAX_APP_SLOTS;

/** Ceiling on a module's declared memory plus tables, applied at shared admission (§3). */
export const DEFAULT_MAX_MODULE_MEMORY_BYTES = 64 * 1024 * 1024; // 64 MiB

/** Modules per bundle, so zero-memory modules cannot make admission an unbounded walk. */
export const DEFAULT_MAX_BUNDLE_MODULES = 256;

export interface MemoryLimits {
  /** Initial size in pages, allocated eagerly at instantiation. */
  initialPages: number;
  /** Declared maximum in pages, or null (unbounded, refused by `checkModuleLimits`). */
  maxPages: number | null;
}

/** Everything a module makes the host allocate by declaring it — linear memory and table
 *  elements — charged to one budget (§4.3). */
export interface ModuleLimits {
  /** The module's own linear memory, or null (then refused by module-table's `memory`
   *  export check). */
  memory: MemoryLimits | null;
  /** Elements over all tables at initial size, reserved at instantiation. */
  initialTableElements: number;
  /** The same at declared maxima, or null when any table declares none (refused). */
  maxTableElements: number | null;
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

/** A `limits` record: flags, initial, then maximum if declared. Shared (0x02) and 64-bit
 *  (0x04+) are outside the §4 contract and refused by name. */
function readLimits(c: Cursor, what: "memory" | "table"): { initial: number; max: number | null } {
  if (c.i >= c.b.length) throw new Error(`wasm: truncated ${what} limits`);
  const flags = c.b[c.i++];
  if (flags & 0x02) throw new Error(`wasm: module declares a shared ${what} — refused (§4.3: a module's memory is private to it)`);
  if (flags & ~0x01) throw new Error(`wasm: unsupported ${what} limits flags 0x${flags.toString(16)}`);
  const initial = readVarU32(c);
  const max = (flags & 0x01) ? readVarU32(c) : null;
  return { initial, max };
}

/** A table type: reftype, then `limits`. Only funcref/externref are read; anything else
 *  would be guessed at, and a misread table is an uncharged one. */
function readTableType(c: Cursor): { initial: number; max: number | null } {
  if (c.i >= c.b.length) throw new Error("wasm: truncated table type");
  const reftype = c.b[c.i++];
  if (reftype !== 0x70 && reftype !== 0x6f) {
    throw new Error(`wasm: unsupported table element type 0x${reftype.toString(16)}`);
  }
  return readLimits(c, "table");
}

/** Read what a module declares it may allocate: its own linear memory (null when it
 *  declares none) and its tables. Throws when the module imports a memory or a table,
 *  declares more than one memory, or cannot be walked. */
export function readModuleLimits(wasm: Uint8Array): ModuleLimits {
  if (wasm.length < 8) throw new Error("wasm: too short to be a module");
  if (!(wasm[0] === 0x00 && wasm[1] === 0x61 && wasm[2] === 0x73 && wasm[3] === 0x6d)) {
    throw new Error("wasm: bad magic (not a WebAssembly module)");
  }
  const c: Cursor = { b: wasm, i: 8 };
  let memory: MemoryLimits | null = null;
  let initialTableElements = 0;
  let maxTableElements: number | null = 0;
  while (c.i < wasm.length) {
    const id = wasm[c.i++];
    const size = readVarU32(c);
    const end = c.i + size;
    if (end > wasm.length) throw new Error("wasm: truncated section");
    if (id === 2) {
      // Imports: functions only (§4.2). An imported memory or table is storage the module
      // did not declare, so it is refused.
      const count = readVarU32(c);
      for (let k = 0; k < count; k++) {
        skipName(c);
        skipName(c);
        if (c.i >= c.b.length) throw new Error("wasm: truncated import");
        const kind = wasm[c.i++];
        if (kind === 0x00) readVarU32(c);                     // func: typeidx
        else if (kind === 0x01) throw new Error("wasm: module imports a table — refused (§4.2: a module imports nothing from the runtime)");
        else if (kind === 0x02) throw new Error("wasm: module imports a memory — refused (§4.2: a module imports nothing from the runtime)");
        else if (kind === 0x03) c.i += 2;                     // global: valtype ‖ mut
        else throw new Error(`wasm: unknown import kind 0x${kind.toString(16)}`);
      }
    } else if (id === 4) {
      // Tables: ordinary compiler output, so charged like pages rather than refused.
      const count = readVarU32(c);
      for (let k = 0; k < count; k++) {
        const t = readTableType(c);
        initialTableElements += t.initial;
        maxTableElements = (maxTableElements === null || t.max === null) ? null : maxTableElements + t.max;
      }
      if (c.i > end) throw new Error("wasm: truncated table section");
    } else if (id === 5) {
      const count = readVarU32(c);
      if (count !== 1) throw new Error(`wasm: ${count} memories declared — a module declares exactly one (§4.1)`);
      const m = readLimits(c, "memory");
      memory = { initialPages: m.initial, maxPages: m.max };
    }
    // Skip to the section end, so an appended field cannot desynchronise the walk.
    c.i = end;
  }
  return { memory, initialTableElements, maxTableElements };
}

/** Host bytes a module's declared maxima amount to. Reached only through
 *  `checkModuleLimits`, which refuses an undeclared maximum before anything sums one. */
export function moduleFootprintBytes(limits: ModuleLimits): number {
  return (limits.memory?.maxPages ?? 0) * WASM_PAGE_BYTES
    + (limits.maxTableElements ?? 0) * WASM_TABLE_ELEMENT_BYTES;
}

/** Refuse a module whose declared memory plus tables do not fit `maxBytes` (§4.3), or
 *  that declares no maximum for either. */
export function checkModuleLimits(wasm: Uint8Array, maxBytes: number): ModuleLimits {
  const limits = readModuleLimits(wasm);
  if (limits.memory && limits.memory.maxPages === null) {
    throw new Error(
      "wasm: module declares no memory maximum — refused, since an embedder cannot impose one after instantiation (build with AssemblyScript's --maximumMemory)",
    );
  }
  if (limits.maxTableElements === null) {
    throw new Error(
      "wasm: module declares a table with no maximum — refused, since an embedder cannot bound its growth after instantiation",
    );
  }
  const initialPages = limits.memory?.initialPages ?? 0;
  const initial = initialPages * WASM_PAGE_BYTES + limits.initialTableElements * WASM_TABLE_ELEMENT_BYTES;
  if (initial > maxBytes) {
    throw new Error(
      `wasm: module declares ${initialPages} initial memory pages and ${limits.initialTableElements} table elements — ${initial} bytes, above the host budget of ${maxBytes}`,
    );
  }
  const max = moduleFootprintBytes(limits);
  if (max > maxBytes) {
    throw new Error(
      `wasm: module declares a maximum of ${limits.memory?.maxPages ?? 0} memory pages and ${limits.maxTableElements} table elements — ${max} bytes, above the host budget of ${maxBytes}`,
    );
  }
  return limits;
}
