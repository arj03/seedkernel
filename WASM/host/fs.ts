// The `fs.*` capability (exported as `seedkernel-wasm/fs`): raw bytes under an
// opaque, flat key. It is the storage-side twin of `net.*` (raw bytes to/from an
// opaque peer id) — see the runtime split, "raw-byte caps in the kernel,
// structure in modules". The kernel knows nothing about content-addressing,
// descriptors, or quota: those are app policy that an application layers on top
// (seedstore's FsBlobStore does exactly that). Only real platform conditions
// surface — a full disk makes `put` throw, and `stat` reports what the backend
// can see.
//
// Keys are opaque and flat (not POSIX paths). Backends may constrain the key
// charset to what maps safely onto their medium (NodeFs requires filesystem-safe
// names); seedstore's keys are hashes plus a short suffix, well within that.

export interface FsStat {
  /** Total bytes stored across all keys (best-effort). */
  used: number;
  /** Bytes the backend believes are still writable — real free space where the
   *  platform exposes it, otherwise a large sentinel. */
  available: number;
}

export interface Fs {
  get(key: string): Uint8Array | null;
  put(key: string, bytes: Uint8Array): void;
  /** Byte length of the value under `key`, or -1 if absent. Existence is `size ≥ 0`
   *  (there is no separate `has`); also lets a policy layer rebuild an index without
   *  reading every value back. */
  size(key: string): number;
  list(prefix?: string): string[];
  /** true if a value was removed, false if the key was already absent. */
  delete(key: string): boolean;
  stat(): FsStat;
}

/** In-RAM Fs. The portable backend for tests and ephemeral nodes, and the shape
 *  a browser backend (OPFS/IndexedDB) will mirror. Stores copies so callers can
 *  reuse their buffers. */
export class MemoryFs implements Fs {
  private readonly map = new Map<string, Uint8Array>();

  get(key: string): Uint8Array | null {
    const v = this.map.get(key);
    return v ? v.slice() : null;
  }
  put(key: string, bytes: Uint8Array): void { this.map.set(key, bytes.slice()); }
  size(key: string): number {
    const v = this.map.get(key);
    return v ? v.length : -1;
  }
  list(prefix?: string): string[] {
    const out: string[] = [];
    for (const k of this.map.keys()) if (!prefix || k.startsWith(prefix)) out.push(k);
    return out;
  }
  delete(key: string): boolean { return this.map.delete(key); }
  stat(): FsStat {
    let used = 0;
    for (const v of this.map.values()) used += v.length;
    return { used, available: Number.MAX_SAFE_INTEGER };
  }
}
