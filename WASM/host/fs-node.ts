// Node backend for the `fs.*` capability (exported as `seedkernel-wasm/fs-node`): one flat
// file per key under a directory, no nested paths. Content-addressing and quota are the
// app's, layered on top.

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
import { FS_AVAILABLE_UNKNOWN } from "../core/fs.js";

export class NodeFs implements Fs {
  constructor(private readonly dir: string) { mkdirSync(dir, { recursive: true }); }

  /** Which keys are representable is `isSafeFsKey` (core/fs.ts), applied over every backend
   *  by `validatedFs` — not restated here, because a backend's copy of that rule is how key
   *  spaces start differing between targets. What this adds is containment: a key that got
   *  this far still holding a separator would escape `dir`. */
  private path(key: string): string {
    if (key.includes("/") || key.includes("\\") || key === "." || key === "..") {
      throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    }
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
      // Concurrently: a directory of a few thousand keys is a few thousand stats, and
      // awaiting them in sequence would make `stat()` the slowest op on the seam.
      const sizes = await Promise.all((await readdir(this.dir)).map((n) => this.size(n)));
      for (const s of sizes) if (s >= 0) used += s;
    } catch { /* dir absent */ }
    let available = FS_AVAILABLE_UNKNOWN;
    try { const s = await statfs(this.dir); available = s.bavail * s.bsize; }
    catch { /* statfs unsupported on this platform/runtime */ }
    return { used, available };
  }
}
