// Module memory bounds, read off the bytes before instantiation (§4.3). Linear memory and
// tables are both charged; an imported or shared one of either is refused. Compute is
// bounded at each target's engine.

/** WebAssembly linear-memory page size. Limits are declared in pages, budgets in bytes. */
export const WASM_PAGE_BYTES = 65536;

/** Host bytes charged per table element (§4.3). A table is host memory a module allocates
 *  by declaring it — the engine reserves every element at instantiation — so admission
 *  charges it against the same budget as linear memory. Measured at ~28 bytes per funcref
 *  entry on V8 and 8 in wazero; the charge is the conservative one, and one number on every
 *  target for the reason `DEFAULT_SCRATCH_SIZE` is. */
export const WASM_TABLE_ELEMENT_BYTES = 32;

/** The I/O region a module reserves at its `scratch` export when it declares no
 *  `scratchSize` (§4.1). One number on every target: a payload the JS table admits and the
 *  Go one refuses is a module that loads on one node and not another. The Go side receives
 *  it from the shared shim at every slot build. */
export const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

/** Default heap cap for a confined guest realm (§12.3). Deliberately equal to
 *  `DEFAULT_MAX_MODULE_MEMORY_BYTES` below, so the two kinds of untrusted code a bundle can
 *  ship are held to one number rather than two that drift. */
export const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default budget per entrypoint invocation (§12.3): guest execution AND the wall clock of
 *  every handoff the invocation makes — queue wait, a parked host call, socket backlog, a
 *  deferred answer. Generous for any real request, and short enough that a wedged guest
 *  frees the host thread. */
export const DEFAULT_GUEST_DEADLINE_MS = 5000;

/** How many deadlines one guest realm may hold at once (§12.3), enforced per realm by the
 *  shell's one timer table per realm. Kept deliberately modest: each deadline is host-side
 *  state, not memory charged to the confined heap. */
export const DEFAULT_MAX_LIVE_TIMERS = 1 << 10;

/** Aggregate bytes of opaque timer bodies retained outside one guest's confined heap.
 *  `timer/arm` copies each body before retaining it, so reusing one in-realm buffer cannot
 *  multiply host memory without meeting this per-realm ceiling. */
export const DEFAULT_MAX_TIMER_PAYLOAD_BYTES = 4 * 1024 * 1024;

/** Unresolved `host.call`s one realm may hold at once. Every call crosses a copy boundary
 *  and retains host-side promise state, so fire-and-forget calls need their own count bound
 *  independent of the guest heap. Paired with the byte ceiling below: neither bound is a
 *  substitute for the other. */
export const DEFAULT_MAX_OUTSTANDING_HOST_CALLS = 1 << 8;

/** Aggregate copied input bytes retained by unresolved `host.call`s in one realm. Eight
 *  maximum-sized network frames leave useful concurrency for ordinary calls while keeping
 *  a stalled destination from turning the caller's confined heap into unbounded host
 *  memory. Applies to every host call, not only networking. */
export const DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES = 16 * 1024 * 1024;

/** Confined realms one node may hold at once (`slots`, shell-core.ts). The MULTIPLICAND:
 *  every per-realm ceiling here is one of these times this number, which is what makes the
 *  node total a ceiling rather than a floor — that sum is added up and measured against a
 *  real machine in tests/verify-hardening.mjs (§12.3). Bounding the count is also
 *  why nothing here is pooled BETWEEN realms: an allowance apps draw on in common is one
 *  app's standing way to refuse another's calls by being busy, while a quota per tenant
 *  times a bounded tenant count reaches the same total with no such channel. Slots are the
 *  operator's own admin path (§12.4), so this bounds an install list, never a peer's reach. */
export const DEFAULT_MAX_APP_SLOTS = 8;

/** One realm's clock share for fresh invocation roots the guest creates ITSELF (§12.3).
 *  Calls descended from existing work inherit its absolute deadline; a fired timer starts
 *  a new one and can re-arm its successor forever. `createRealmTimers` gives that root a
 *  causal clock which follows continuations and cross-realm descendants, debiting measured
 *  execution rather than I/O wait. Twice the slot count keeps those self-created roots to
 *  half a CPU in steady state after the initial bank. It does not cap the rate of peer- or
 *  host-created roots and is therefore not a node-wide CPU total. */
export const SELF_INITIATED_CLOCK_DIVISOR = 2 * DEFAULT_MAX_APP_SLOTS;

/** Default ceiling on a module's declared footprint — linear memory AND the tables it
 *  declares, which are host memory bought with a declaration just as pages are. Applied at
 *  the shared admission path (§3) against the tighter of this and the target loader's own
 *  ceiling (`PureModuleLoader.maxModuleMemoryBytes`), so a host may hold its isolates to
 *  less and none can be looser about what a bundle may land. */
export const DEFAULT_MAX_MODULE_MEMORY_BYTES = 64 * 1024 * 1024; // 64 MiB

/** Metadata bound for one signed bundle. Aggregate module memory normally binds first, but
 *  zero-memory declarations must not turn admission into an unbounded module-array walk. */
export const DEFAULT_MAX_BUNDLE_MODULES = 256;

/** The default in-memory `Fs` backend's whole quota (host/fs-memory.ts `MemoryFs`), so a
 *  successful put cannot turn bounded in-flight calls into unbounded permanent process RAM.
 *  Declared here rather than in fs-memory.ts so one file holds every node-scoped ceiling
 *  the §12.3 sum adds up; fs-memory.ts re-exports it. */
export const DEFAULT_MEMORY_FS_MAX_BYTES = 64 * 1024 * 1024;
export const DEFAULT_MEMORY_FS_MAX_ENTRIES = 1 << 16;

export interface MemoryLimits {
  /** Initial size in pages — allocated eagerly at instantiation, so it decides whether
   *  instantiating the module is itself an attack. */
  initialPages: number;
  /** Declared maximum in pages, or null when the module declares none — an undeclared
   *  maximum is an unbounded one, so the host refuses it (see `checkModuleLimits`). */
  maxPages: number | null;
}

/** Everything one module can make a host allocate by declaring it: linear memory, and the
 *  elements of the tables its language runtime uses for indirect calls. Both are read on
 *  one walk and charged to one budget — a table is real host memory (§4.3), so bounding
 *  only the pages would leave the same exhaustion open under another section header. */
export interface ModuleLimits {
  /** The module's own linear memory, or null when it declares none. Null is not a pass —
   *  it means the module exports no memory of its own, which module-table's `memory`
   *  export check then refuses with its own message. */
  memory: MemoryLimits | null;
  /** Elements summed over the module's tables at their initial size, reserved eagerly at
   *  instantiation exactly as initial memory pages are. */
  initialTableElements: number;
  /** The same at their declared maxima, or null when any table declares none — `table.grow`
   *  makes that unbounded, refused for the reason an undeclared memory maximum is. */
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

/** A `limits` record: flags byte, then the initial size, then the maximum if declared.
 *  Flags above 0x01 mean a shared memory or table (0x02/0x03) or a 64-bit index type
 *  (0x04+), both outside the §4 pure-transform contract — refused by name so the message
 *  says why. */
function readLimits(c: Cursor, what: "memory" | "table"): { initial: number; max: number | null } {
  if (c.i >= c.b.length) throw new Error(`wasm: truncated ${what} limits`);
  const flags = c.b[c.i++];
  if (flags & 0x02) throw new Error(`wasm: module declares a shared ${what} — refused (§4.3: a module's memory is private to it)`);
  if (flags & ~0x01) throw new Error(`wasm: unsupported ${what} limits flags 0x${flags.toString(16)}`);
  const initial = readVarU32(c);
  const max = (flags & 0x01) ? readVarU32(c) : null;
  return { initial, max };
}

/** A table type: element reference type, then a `limits` record. Only the two reference
 *  types a §4 module's toolchain emits are read — a typed function reference or the
 *  table-with-initializer form would have to be guessed at, and a table this walk misreads
 *  is a table it fails to charge. */
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
      // Import section. A module imports nothing from the runtime but its own language
      // runtime's shims, which are functions (§4.2); an imported memory or table would hand
      // a pure transform storage it did not declare, so it is refused rather than counted.
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
      // Table section. Charged rather than refused: a table is ordinary compiler output for
      // indirect calls. Its elements are host memory the module never has to touch — the
      // engine reserves the initial count at instantiation and `table.grow` reaches the
      // declared maximum — so they are budgeted like pages.
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
    // Sections this does not read are skipped wholesale, as is any tail left inside one it
    // does — so a future field appended to a section cannot desynchronise the walk.
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

/** Refuse a module whose declared memory and tables do not fit `maxBytes` (§4.3). An
 *  undeclared maximum — memory's or a table's — is unbounded, so it is refused. The two are
 *  charged together: one budget for what the module may allocate, not one budget each. */
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
