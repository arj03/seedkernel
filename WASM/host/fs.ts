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

/** A scope prefix must survive the backend's key rules. Both real backends map a key
 *  to a *filename* and enforce this class (`fs-node.ts`, `native/fs.go`), so a prefix
 *  outside it makes every scoped write fail — checked here, at construction, rather
 *  than on the first `put`. */
const SAFE_SCOPE = /^[A-Za-z0-9._-]+$/;

/** Scope a backend to one app's private keyspace (README §12.2).
 *
 *  Without this, every app granted the `fs` domain shares one flat keyspace: `FS_LIST`
 *  with an empty prefix enumerates every key on the node, `FS_GET` reads any of them and
 *  `FS_DELETE` removes any of them. That is the one place the runtime's "ownership is
 *  structural" property (§5.1) did not hold — kernel *names* carry their author, so one
 *  app's modules are unreachable to another by construction, but fs *keys* carried
 *  nothing and were reachable to everyone. This closes that asymmetry the same way the
 *  names do: by derivation, not by a rule something has to enforce.
 *
 *  `scope` is an opaque prefix derived from the app key by `appScopeFor` (bundle.ts) —
 *  derived there rather than here because it needs a hash, and this module stays
 *  dependency-free. Two properties matter and both come from that derivation: it lies
 *  inside the backend's key charset, and it is fixed-length, so distinct scopes cannot
 *  overlap however an author names the app. (An app name may itself contain `:`, so a
 *  plain `appKey + separator` prefix would let app `x` key `y:z` collide with app `x:y`
 *  key `z` — and would be rejected by both backends anyway.)
 *
 *  `stat()` is deliberately NOT scoped — `used`/`available` describe the physical
 *  backend, and reporting a per-app figure for `available` would be a fiction. An app
 *  that wants its own footprint sums `size()` over its own `list()`, which is now
 *  exactly its own keys. */
export function scopedFs(inner: Fs, scope: string): Fs {
  if (!SAFE_SCOPE.test(scope)) throw new Error(`fs: unsafe scope ${JSON.stringify(scope)}`);
  const outward = (key: string): string => scope + key;
  return {
    get: (key) => inner.get(outward(key)),
    put: (key, bytes) => inner.put(outward(key), bytes),
    size: (key) => inner.size(outward(key)),
    // An absent prefix means "everything I can see", which is now everything in this
    // scope and nothing else. Keys come back stripped, so the guest only ever handles
    // the names it chose and the scope stays a host-side fact.
    list: (prefix) => inner.list(outward(prefix ?? "")).map((k) => k.slice(scope.length)),
    delete: (key) => inner.delete(outward(key)),
    stat: () => inner.stat(),
  };
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
