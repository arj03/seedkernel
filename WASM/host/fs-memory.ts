// The in-RAM `Fs` backend — the portable one, for tests and ephemeral nodes, and the
// shape a browser backend (OPFS/IndexedDB) will mirror.
//
// A backend, so it sits with the other backends (`fs-node.ts`, and Go's `native/fs.go`)
// rather than in core. What is core is the seam it satisfies and the key rule
// (`Fs`, `isSafeFsKey` — core/fs.ts); the wrappers that apply the rule and the app
// scoping (`validatedFs`, `scopedFs`) live in shell-core.ts with the shell that wires
// them. Those decide what an app can reach, and every host must agree on them. Which
// medium the bytes land in decides nothing, so a target picks a backend the way it
// picks a socket implementation.

import { FS_AVAILABLE_UNKNOWN, type Fs, type FsStat } from "../core/fs.js";

/** In-RAM Fs. Stores copies so callers can reuse their buffers.
 *
 *  Every method is `async` even though the map behind them is not: the seam is what is
 *  asynchronous, and a backend that resolved sometimes-immediately would let a caller
 *  work by accident on this one and fail on the backend it ships against. */
export class MemoryFs implements Fs {
  private readonly map = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | null> {
    const v = this.map.get(key);
    return v ? v.slice() : null;
  }
  async put(key: string, bytes: Uint8Array): Promise<void> { this.map.set(key, bytes.slice()); }
  async size(key: string): Promise<number> {
    const v = this.map.get(key);
    return v ? v.length : -1;
  }
  async list(prefix?: string): Promise<string[]> {
    const out: string[] = [];
    for (const k of this.map.keys()) if (!prefix || k.startsWith(prefix)) out.push(k);
    return out;
  }
  async delete(key: string): Promise<boolean> { return this.map.delete(key); }
  async stat(): Promise<FsStat> {
    let used = 0;
    for (const v of this.map.values()) used += v.length;
    return { used, available: FS_AVAILABLE_UNKNOWN };
  }
}
