// Pre-instantiation bounds on a module's declared linear memory (README §4.3),
// plus the shared §12.3 guest-realm bounds that are deliberately the same number
// (the realm heap cap and the module memory ceiling — see DEFAULT_REALM_MEMORY_BYTES)
// and the §4.1 scratch default every host's table must agree on.
//
// §4.3 bounds two things an installed module may CONSUME; this file bounds the memory.
// It cannot be bounded *after* instantiation — `new WebAssembly.Instance` allocates the
// declared initial memory before any export runs, so a module declaring 4 GiB has already
// taken the host down by the time module-table.ts's scratch validation sees it. The bound
// has to be read off the bytes first, which is what this file is for. (Compute is the
// other, and it is bounded at each target's engine rather than here: a call carries the
// calling guest's remaining execution segment (§12.3) as its deadline, landed by killing
// the module's worker on the JS targets (module-table.ts) and by wazero's
// `WithCloseOnContextDone` on the native one — armed by default on both, the native
// side defaulting to DEFAULT_GUEST_DEADLINE_MS below and retunable through
// native/main.go's `SEEDKERNEL_MODULE_DEADLINE_MS`.)
//
// The JS WebAssembly API exposes no memory limits on a compiled `Module`, so this walks
// the binary's section headers and reads the limits directly. It is a *bounds read*, not
// a validator: the engine still does real validation at compile time. Anything this
// cannot parse is refused rather than waved through, because a module whose sections do
// not parse is one whose memory footprint cannot be bounded either — and the §4 module
// contract is narrow enough (three exports, no imports but the AS shims) that a module
// with an unparseable prologue is not a module.
//
// Two refusals here are structural rather than budgetary, and both defend claims §4.3
// already makes in prose:
//   - an *imported* memory would be host-supplied, which is the one way a pure transform
//     could reach bytes it did not declare (§4.2: modules import nothing);
//   - a *shared* memory would be visible to another agent, breaking "a buggy or malicious
//     module ... cannot touch the host or another module" (§4.3).

/** WebAssembly linear-memory page size. Limits are declared in pages, budgets in bytes. */
export const WASM_PAGE_BYTES = 65536;

/** The I/O region a module reserves at its `scratch` export when it declares no
 *  `scratchSize` (README §4.1). One number on every target: the JS table
 *  (module-table.ts) and the Go table (native/main.go) must not disagree about how
 *  much of a module's memory is its staging area — a payload the JS host admits
 *  and Go refuses (or vice versa) is a module that loads on one node and not
 *  another. The Go side receives it from the shared shim at every bindAll. */
export const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

/** Default heap cap for a confined guest realm (README §12.3, §16.1) — applied by
 *  the shell when no target overrides it, and by the realm factories for a direct
 *  caller. It deliberately equals `DEFAULT_MAX_MODULE_MEMORY_BYTES` below, so the
 *  two kinds of untrusted code a bundle can ship are held to one number; the two
 *  factories used to each own their own 64 MiB copy that could drift from this. */
export const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default budget of guest execution time per entrypoint invocation (README §12.3,
 *  §16.1). Generous for any real request — the storage guest's heaviest local pass
 *  is orders of magnitude under it — and short enough that a wedged guest frees
 *  the single host thread rather than holding it forever. The shell applies it
 *  when no target overrides; the realm factories use it for a direct caller. */
export const DEFAULT_GUEST_DEADLINE_MS = 5000;

/** How many deadlines one guest realm may hold at once (README §12.3). A guest cannot
 *  create a timer for itself — there is no `setTimeout` in a fresh QuickJS context — so
 *  every live one is an entry in a host-side table, and an unbounded `timer/arm` loop
 *  would be a guest spending the host's memory rather than its own heap. Here with the
 *  other two realm bounds because it is the same kind of number and applied by the same
 *  code: the shell wires one timer table per realm, so the cap is per realm too. */
export const DEFAULT_MAX_LIVE_TIMERS = 1 << 16;

/** Default ceiling on a module's declared linear memory. Matches the guest realm's
 *  default heap cap (safe-js.ts), so the two kinds of untrusted code a bundle can ship
 *  are held to one number rather than to two that drift.
 *
 *  Declared here rather than in a host, because `installBundle` applies it on the shared
 *  admission path (bundle.ts) — the rule that must not differ between the JS host and the
 *  Go one (§3: "what genuinely must not diverge between hosts is the bundle load order
 *  and the admission rules"). A host may hold its own direct installs to something
 *  tighter; no host may be looser about what a *bundle* may land. */
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
      // Import section. A module imports nothing from the runtime — only its own
      // language runtime's shims, which are functions (§4.2); an imported memory is the
      // one import that would hand a pure transform bytes it did not declare, so it is
      // refused rather than counted.
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
 *  Both halves of the budget matter and they fail for different reasons. `initialPages`
 *  is allocated at instantiation, so an oversized one is an attack that lands the moment
 *  the module is compiled — it must be checked before `WebAssembly.Instance` exists.
 *  `maxPages` bounds `memory.grow` afterwards, and a module that declares **no** maximum
 *  is refused outright: WebAssembly gives the embedder no way to impose one after the
 *  fact, so an undeclared maximum is an unbounded one. That makes "declare your ceiling"
 *  part of the module contract rather than a hope — the cost is one build flag
 *  (AssemblyScript's `--maximumMemory`, in pages), and the benefit is that the §4.3
 *  memory residual is closed by construction rather than by a deployment note.
 *
 *  Returns the limits it validated (null when the module declares no memory of its own,
 *  which the `memory` export check refuses separately). */
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
