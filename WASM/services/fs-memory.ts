// The in-memory `Fs` backend: portable, for tests and ephemeral nodes. The other backends
// are `fs-node.ts` and Go's `native/fs.go`; the seam is `fs.ts`. The per-app key rule is
// applied in host/fs-view.ts, so what an app can reach does not depend on the backend.

import { type Fs, type FsStat } from "./fs.js";

/** The in-memory backend's total quota, so puts cannot grow process memory without
 *  bound. */
export const DEFAULT_MEMORY_FS_MAX_BYTES = 64 * 1024 * 1024;
export const DEFAULT_MEMORY_FS_MAX_ENTRIES = 1 << 16;

/** In-memory Fs. Stores copies so callers can reuse their buffers.
 *
 *  Every method is `async` even though the map is not, so code that accidentally relies
 *  on synchronous results fails here too and not only on a real backend. */
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
    // Checked before the copy, committed after it, so a failed allocation leaves the old
    // value and the accounting intact. `new Uint8Array` because a Node Buffer's slice()
    // aliases the caller's storage.
    const stored = new Uint8Array(bytes);
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
