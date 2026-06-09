// Node backend for the `fs.*` capability (exported as `seedkernel-wasm/fs-node`),
// the storage twin of `net-node`. One flat file per key under a directory; no
// nested paths. Migrated up from seedstore's old path-based FsOps — the raw
// syscalls now live in the runtime, and the storage app layers content-addressing
// and quota on top (the runtime split).

import {
  mkdirSync, readdirSync, readFileSync, writeFileSync, unlinkSync, statSync, statfsSync,
} from "node:fs";
import { join } from "node:path";

import type { Fs, FsStat } from "./fs.js";

// An opaque key becomes a filename verbatim, so it must be a safe, flat name:
// no separators, no `..`, nothing that could escape the directory. seedstore's
// keys (hex block-ids + a short suffix) satisfy this; anything else is rejected
// rather than silently mangled.
const SAFE_KEY = /^[A-Za-z0-9._-]+$/;

export class NodeFs implements Fs {
  constructor(private readonly dir: string) { mkdirSync(dir, { recursive: true }); }

  private path(key: string): string {
    if (!SAFE_KEY.test(key)) throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    return join(this.dir, key);
  }

  get(key: string): Uint8Array | null {
    try { return new Uint8Array(readFileSync(this.path(key))); } catch { return null; }
  }
  put(key: string, bytes: Uint8Array): void { writeFileSync(this.path(key), bytes); }
  has(key: string): boolean { return this.size(key) >= 0; }
  size(key: string): number {
    try { return statSync(this.path(key)).size; } catch { return -1; }
  }
  list(prefix?: string): string[] {
    let names: string[];
    try { names = readdirSync(this.dir); } catch { return []; }
    return prefix ? names.filter((n) => n.startsWith(prefix)) : names;
  }
  delete(key: string): boolean {
    try { unlinkSync(this.path(key)); return true; } catch { return false; }
  }
  stat(): FsStat {
    let used = 0;
    try { for (const n of readdirSync(this.dir)) { const s = this.size(n); if (s >= 0) used += s; } }
    catch { /* dir absent */ }
    let available = Number.MAX_SAFE_INTEGER;
    try { const s = statfsSync(this.dir); available = s.bavail * s.bsize; }
    catch { /* statfs unsupported on this platform/runtime */ }
    return { used, available };
  }
}
