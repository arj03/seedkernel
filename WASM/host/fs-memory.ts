// The in-RAM `Fs` backend — the portable one, for tests and ephemeral nodes, and the shape
// a browser backend (OPFS/IndexedDB) will mirror. It sits with the other backends
// (`fs-node.ts`, Go's `native/fs.go`), not in core: core is the seam it satisfies and the
// key rule (core/fs.ts), with the wrappers that apply them in shell-core.ts — those decide
// what an app can reach. Which medium the bytes land in decides nothing.

import { type Fs, type FsStat } from "../core/fs.js";
// The quotas live in core/wasm-limits.ts so its derived node-memory ceiling can name them
// without core importing a host file; re-exported here, where they are applied.
import { DEFAULT_MEMORY_FS_MAX_BYTES, DEFAULT_MEMORY_FS_MAX_ENTRIES } from "../core/wasm-limits.js";
export { DEFAULT_MEMORY_FS_MAX_BYTES, DEFAULT_MEMORY_FS_MAX_ENTRIES } from "../core/wasm-limits.js";

/** In-RAM Fs. Stores copies so callers can reuse their buffers.
 *
 *  Every method is `async` even though the map behind them is not: the seam is what is
 *  asynchronous, and a backend that resolved even sometimes-immediately would let a caller
 *  work by accident on this one and fail on the backend it ships against. */
export class MemoryFs implements Fs {
  private readonly map = new Map<string, Uint8Array>();
  private used = 0;

  constructor(
    private readonly maxBytes = DEFAULT_MEMORY_FS_MAX_BYTES,
    private readonly maxEntries = DEFAULT_MEMORY_FS_MAX_ENTRIES,
  ) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0
      || !Number.isSafeInteger(maxEntries) || maxEntries < 0) {
      throw new Error("memory-fs: invalid quota");
    }
  }

  async get(key: string): Promise<Uint8Array | null> {
    const v = this.map.get(key);
    return v ? v.slice() : null;
  }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    const previous = this.map.get(key);
    if (!previous && this.map.size >= this.maxEntries) {
      throw new Error(`memory-fs: entry quota exceeded (cap ${this.maxEntries})`);
    }
    const nextUsed = this.used - (previous?.length ?? 0) + bytes.length;
    if (nextUsed > this.maxBytes) {
      throw new Error(`memory-fs: byte quota exceeded (cap ${this.maxBytes})`);
    }
    // Checked before the copy, committed after it: a failed allocation leaves the old
    // value and the accounting intact.
    const stored = bytes.slice();
    this.map.set(key, stored);
    this.used = nextUsed;
  }
  async size(key: string): Promise<number> {
    const v = this.map.get(key);
    return v ? v.length : -1;
  }
  async list(prefix?: string): Promise<string[]> {
    const out: string[] = [];
    for (const k of this.map.keys()) if (!prefix || k.startsWith(prefix)) out.push(k);
    return out;
  }
  async delete(key: string): Promise<boolean> {
    const previous = this.map.get(key);
    if (!previous) return false;
    this.map.delete(key);
    this.used -= previous.length;
    return true;
  }
  async stat(): Promise<FsStat> {
    return { used: this.used, available: this.maxBytes - this.used };
  }
}
