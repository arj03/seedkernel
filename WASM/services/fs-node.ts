// Node backend for the `fs` service (exported as `seedkernel-wasm/fs-node`): one flat
// file per key under a directory, no nested paths. Content addressing and quotas are up
// to the app.

import { mkdirSync } from "node:fs";
// Truly async, not sync calls in an async wrapper, so a node serving requests does not
// block its only thread on disk. `mkdirSync` is the exception: it runs once, in the
// constructor, which cannot return a promise.
import {
  readdir, readFile, writeFile, unlink, stat, statfs,
} from "node:fs/promises";
import { join } from "node:path";

import type { Fs, FsStat } from "./fs.js";
import { FS_AVAILABLE_UNKNOWN } from "./fs.js";

export class NodeFs implements Fs {
  private used = 0;
  private initialized: Promise<void> | undefined;
  private readonly mutations = new Map<string, Promise<void>>();

  constructor(private readonly dir: string) { mkdirSync(dir, { recursive: true }); }

  /** One scan before the first mutation or `stat`. This instance assumes it is the only
   *  writer to its directory; reopen it to pick up outside changes, as on native. The scan
   *  limits concurrent stats so opening a large store does not flood the I/O pool. */
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

  /** Serialize writes to the same file so its size delta is accounted correctly;
   *  unrelated files stay parallel. Names that may alias (case, trailing dots) share a
   *  queue even on case-sensitive filesystems. Only the queue key is normalized, never the
   *  filename. */
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

  /** Which keys are valid is `isSafeFsKey` (services/fs.ts), applied over every backend by
   *  `validatedFs`, and deliberately not duplicated here so targets cannot drift. This only
   *  adds containment: a key with a separator would escape `dir`. */
  private path(key: string): string {
    if (key.includes("/") || key.includes("\\") || key === "." || key === "..") {
      throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    }
    return join(this.dir, key);
  }

  async get(key: string): Promise<Uint8Array | null> {
    try {
      const b = await readFile(this.path(key));
      // A plain Uint8Array view, so slice() copies (unlike Buffer's) without copying the
      // read here.
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
