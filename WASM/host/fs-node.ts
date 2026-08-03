// Node backend for the `fs.*` capability (exported as `seedkernel-wasm/fs-node`),
// the storage twin of `net-node`. One flat file per key under a directory; no
// nested paths. Migrated up from seedstore's old path-based FsOps — the raw
// syscalls now live in the runtime, and the storage app layers content-addressing
// and quota on top (the runtime split).

import { mkdirSync } from "node:fs";
// The seam is async (core/fs.ts), so this backend is genuinely async rather than sync
// calls in an async wrapper: a node serving requests should not block its only thread on
// a disk read. `mkdirSync` is the exception and stays sync — it runs once, in the
// constructor, where there is no promise to return.
import {
  readdir, readFile, writeFile, unlink, stat, statfs,
} from "node:fs/promises";
import { join } from "node:path";

import type { Fs, FsStat } from "../core/fs.js";

// An opaque key becomes a filename verbatim, so it must be a safe, flat name:
// no separators, no `.`/`..`, nothing that could escape the directory.
// seedstore's keys (hex block-ids + a short suffix) satisfy this; anything else
// is rejected rather than silently mangled. The lookahead excludes the bare
// dot names, which are directory references, not files.
const SAFE_KEY = /^(?!\.{1,2}$)[A-Za-z0-9._-]+$/;

// Windows resolves these device names before touching the filesystem: opening
// "CON"/"NUL"/"COM1"… (with or without an extension) hits the console, null, or
// serial device, not a file. Rejected on every OS so the key space is identical
// across Go and Bun nodes.
const fsReserved = new Set<string>(["CON", "PRN", "AUX", "NUL"]);
for (let i = 0; i <= 9; i++) {
  fsReserved.add("COM" + i);
  fsReserved.add("LPT" + i);
}

function fsReservedName(k: string): boolean {
  const dot = k.indexOf(".");
  const stem = dot >= 0 ? k.slice(0, dot) : k;
  return fsReserved.has(stem.toUpperCase());
}

export class NodeFs implements Fs {
  constructor(private readonly dir: string) { mkdirSync(dir, { recursive: true }); }

  private path(key: string): string {
    if (!SAFE_KEY.test(key)) throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    if (fsReservedName(key)) throw new Error(`fs: reserved device name ${JSON.stringify(key)}`);
    return join(this.dir, key);
  }

  async get(key: string): Promise<Uint8Array | null> {
    try { return new Uint8Array(await readFile(this.path(key))); } catch { return null; }
  }
  async put(key: string, bytes: Uint8Array): Promise<void> { await writeFile(this.path(key), bytes); }
  async size(key: string): Promise<number> {
    try { return (await stat(this.path(key))).size; } catch { return -1; }
  }
  async list(prefix?: string): Promise<string[]> {
    let names: string[];
    try { names = await readdir(this.dir); } catch { return []; }
    return prefix ? names.filter((n) => n.startsWith(prefix)) : names;
  }
  async delete(key: string): Promise<boolean> {
    try { await unlink(this.path(key)); return true; } catch { return false; }
  }
  async stat(): Promise<FsStat> {
    let used = 0;
    try {
      // One pass, concurrently: a directory of a few thousand keys is a few thousand
      // stats, and awaiting them in sequence would make `stat()` the slowest op on the
      // seam for no reason. Absent entries (-1) are simply not counted.
      const sizes = await Promise.all((await readdir(this.dir)).map((n) => this.size(n)));
      for (const s of sizes) if (s >= 0) used += s;
    } catch { /* dir absent */ }
    let available = Number.MAX_SAFE_INTEGER;
    try { const s = await statfs(this.dir); available = s.bavail * s.bsize; }
    catch { /* statfs unsupported on this platform/runtime */ }
    return { used, available };
  }
}
