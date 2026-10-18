// The §4 module ABI, once for every target: what a private module must export, and one
// call through its scratch window. Self-contained, with no imports and nothing captured
// from this file, because the JS targets run it inside each module's worker by its source
// text (module-table.ts); the native target runs it in the host realm over the engine
// table (platform.ts).

/** What the ABI needs of one module instance. */
export interface ModuleView {
  /** The `handle` export, or undefined when there is none. Its answer is the response
   *  length, or anything else for a failure. */
  handle: ((len: number) => unknown) | undefined;
  /** An exported global's value, or null when there is none by that name. */
  global(name: string): number | null;
  /** Linear memory in bytes, or a negative number when the module exports none. */
  memoryBytes(): number;
  read(ptr: number, len: number): Uint8Array;
  write(ptr: number, bytes: Uint8Array): void;
  /** Zero `len` bytes at `ptr`. */
  wipe(ptr: number, len: number): void;
}

/** A module checked against §4 (§4.1): it exports `memory`, a `scratch` offset and
 *  `handle`, and reserves `scratchSize` bytes at the offset, at least `scratchDefault`
 *  (the default when it declares none), inside its memory. Throws what is wrong. A call
 *  writes the request at the offset, runs `handle(length)`, and reads the response back
 *  from the same place, answering null when it is too large or `handle` answers no valid
 *  length. Both are wiped afterwards, so neither lingers in a long-lived instance. A throw
 *  from `handle` (a trap) is the caller's. */
export function scratchModule(m: ModuleView, scratchDefault: number):
  { size: number; call(payload: Uint8Array): Uint8Array | null } {
  const memory = m.memoryBytes();
  if (memory < 0) throw new Error("module missing export: memory");
  const scratch = m.global("scratch");
  if (scratch === null) throw new Error("module missing export: scratch");
  const handle = m.handle;
  if (typeof handle !== "function") throw new Error("module missing export: handle");
  const declared = m.global("scratchSize");
  if (declared !== null && !(declared >= scratchDefault)) {
    throw new Error(`invalid scratchSize ${declared} (must be >= ${scratchDefault})`);
  }
  const size = declared ?? scratchDefault;
  if (!(scratch > 0) || scratch + size > memory) {
    throw new Error(`scratch offset ${scratch} out of bounds (memory ${memory})`);
  }
  return {
    size,
    call(payload) {
      if (payload.length > size) return null;
      let wipe = payload.length;
      try {
        m.write(scratch, payload);
        const len = handle(payload.length);
        if (typeof len !== "number" || !(len >= 0 && len <= size)) return null;
        wipe = Math.max(wipe, len);
        return m.read(scratch, len);
      } finally {
        try { m.wipe(scratch, wipe); } catch { /* a trapped or closed instance */ }
      }
    },
  };
}

/** The imports a module may make: AssemblyScript's three runtime shims and nothing else,
 *  the same set on every target, so whether a module loads never depends on the target.
 *  `abort` traps (a module calls it where it found itself broken, §4.2), `seed` is a
 *  constant (a pure transform reads no clock) and `trace` drops its arguments. */
export function moduleShims(): { env: Record<string, (...args: number[]) => number | void> } {
  return {
    env: {
      abort: (_msg: number, _file: number, line: number, col: number) => {
        throw new Error("module abort at " + line + ":" + col);
      },
      seed: () => 0,
      trace: () => {},
    },
  };
}
