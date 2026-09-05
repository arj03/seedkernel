// Node backend for the `fs.*` capability (exported as `seedkernel-wasm/fs-node`): one flat
// file per key under a directory, no nested paths. Content-addressing and quota are the
// app's, layered on top.

import { mkdirSync, renameSync, writeFileSync } from "node:fs";
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

/** Write a whole file or none: a temp beside the target, then a rename onto it. A bare
 *  `writeFileSync` truncates in place, so a crash mid-write leaves a partial file that the
 *  next boot reads as something else entirely. Node-local and sync, because both callers
 *  are boot-time state a node cannot start without (main-node.ts, shell-node.ts). */
export function writeFileAtomic(path: string, data: Uint8Array | string, mode?: number): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, mode === undefined ? undefined : { mode });
  renameSync(tmp, path);
}

export class NodeFs implements Fs {
  private used = 0;
  private initialized: Promise<void> | undefined;
  private readonly mutations = new Map<string, Promise<void>>();

  constructor(private readonly dir: string) { mkdirSync(dir, { recursive: true }); }

  /** One scan before the first mutation or statistics query. This instance owns writes
   *  to its directory; reopen it to account for out-of-band changes, as on native.
   *  Limit the scan's concurrent stats so opening a large store cannot flood the I/O pool. */
  private initialize(): Promise<void> {
    if (this.initialized) return this.initialized;
    const scan = (async () => {
      const names = await readdir(this.dir);
      let used = 0;
      for (let i = 0; i < names.length; i += 32) {
        const sizes = await Promise.all(names.slice(i, i + 32).map((n) => this.size(n)));
        for (const size of sizes) if (size >= 0) used += size;
      }
      this.used = used;
    })();
    this.initialized = scan;
    void scan.catch(() => { this.initialized = undefined; }); // a failed open can be retried
    return scan;
  }

  /** Order writes to the same file around its size delta; unrelated files stay parallel.
   *  Conservatively group case/trailing-dot aliases even on case-sensitive filesystems.
   *  Only the queue key is normalized, never the actual filename. */
  private mutate<T>(key: string, action: () => Promise<T>): Promise<T> {
    const queueKey = key.toLowerCase().replace(/[. ]+$/, "");
    const previous = this.mutations.get(queueKey);
    const result = (async () => {
      await previous;
      await this.initialize();
      return action();
    })();
    const settled = result.then(() => {}, () => {});
    this.mutations.set(queueKey, settled);
    void settled.then(() => {
      if (this.mutations.get(queueKey) === settled) this.mutations.delete(queueKey);
    });
    return result;
  }

  /** Which keys are representable is `isSafeFsKey` (core/fs.ts), applied over every backend
   *  by `validatedFs` — not restated here, because a backend's copy of that rule is how key
   *  spaces start differing between targets. What this adds is containment: a key that got
   *  this far while still holding a separator would escape `dir`. */
  private path(key: string): string {
    if (key.includes("/") || key.includes("\\") || key === "." || key === "..") {
      throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    }
    return join(this.dir, key);
  }

  async get(key: string): Promise<Uint8Array | null> {
    try {
      const b = await readFile(this.path(key));
      // A plain view keeps Uint8Array.slice's copying semantics without copying the read.
      return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    } catch { return null; }
  }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    const path = this.path(key);
    return this.mutate(key, async () => {
      const old = Math.max(0, await this.size(key));
      let next = bytes.byteLength;
      try { await writeFile(path, bytes); }
      catch (err) {
        // A failed write may already have truncated or partially replaced the file.
        next = Math.max(0, await this.size(key));
        throw err;
      }
      finally { this.used += next - old; }
    });
  }
  async size(key: string): Promise<number> {
    try { return (await stat(this.path(key))).size; } catch { return -1; }
  }
  async list(prefix?: string): Promise<string[]> {
    let names: string[];
    try { names = await readdir(this.dir); } catch { return []; }
    return prefix ? names.filter((n) => n.startsWith(prefix)) : names;
  }
  async delete(key: string): Promise<boolean> {
    try {
      const path = this.path(key);
      return await this.mutate(key, async () => {
        const old = Math.max(0, await this.size(key));
        await unlink(path);
        this.used -= old;
        return true;
      });
    } catch { return false; }
  }
  async stat(): Promise<FsStat> {
    await this.initialize();
    let available = FS_AVAILABLE_UNKNOWN;
    try { const s = await statfs(this.dir); available = s.bavail * s.bsize; }
    catch { /* statfs unsupported on this platform/runtime */ }
    return { used: this.used, available };
  }
}
