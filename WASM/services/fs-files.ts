// The `fs` store over raw files (§12.1): one flat file per key under a directory, the same
// on every target. A platform supplies only whole-file primitives (`RawFiles`); the key
// store above them (space accounting, crash-temp cleanup, per-key write order) is here.

import type { Fs, FsStat } from "./fs.js";
import { FS_AVAILABLE_UNKNOWN } from "./fs.js";

/** Bytes a platform hands over; either form is the caller's to keep. */
type Bytes = ArrayBuffer | Uint8Array;
type Maybe<T> = T | Promise<T>;

/** Whole files by path, as a platform offers them (host/abi.ts `PlatformFs`). */
export interface RawFiles {
  /** Create a directory and its parents. */
  mkdir(dir: string): Maybe<void>;
  /** A whole file, or `null` when it is absent or larger than `maxBytes`. */
  read(path: string, maxBytes: number): Maybe<Bytes | null>;
  /** Write a whole file atomically, through a sibling temp file whose name starts with
   *  `~`; a crash can leave that file behind. */
  write(path: string, bytes: Uint8Array): Maybe<void>;
  /** false when there was nothing to remove. */
  remove(path: string): Maybe<boolean>;
  /** A regular file's size, or -1 when there is none. */
  size(path: string): Maybe<number>;
  /** The names in a directory, `\n`-joined. */
  list(dir: string): Maybe<string>;
  /** Free bytes on the directory's volume, or -1 when the platform cannot tell. */
  available(dir: string): Maybe<number>;
}

/** Marks a platform's temp files; `~` is outside the key charset. */
const TMP_PREFIX = "~";

/** No value is larger than one fs/put can carry (host/wasm-limits.ts
 *  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES), so a bigger file planted in the store is never
 *  read into memory. */
const MAX_VALUE_BYTES = 16 << 20;

const u8 = (b: Bytes): Uint8Array => (b instanceof Uint8Array ? b : new Uint8Array(b));

export class FilesFs implements Fs {
  private used = 0;
  private initialized: Promise<void> | undefined;
  private readonly mutations = new Map<string, Promise<void>>();

  constructor(private readonly files: RawFiles, private readonly dir: string) {}

  /** The directory, then one scan of it, before the first mutation or `stat`. This instance assumes it is the only
   *  writer to its directory; reopen it to pick up outside changes. The scan limits
   *  concurrent stats so opening a large store does not flood a platform's I/O, and
   *  reclaims the temp files a crash left behind. */
  private initialize(): Promise<void> {
    if (this.initialized) return this.initialized;
    const scan = (async () => {
      await this.files.mkdir(this.dir);
      const names = await this.names(true);
      let used = 0;
      for (let i = 0; i < names.length; i += 32) {
        const sizes = await Promise.all(names.slice(i, i + 32).map(async (n) => {
          if (!n.startsWith(TMP_PREFIX)) return this.files.size(this.path(n));
          await this.files.remove(this.path(n));
          return -1;
        }));
        for (const size of sizes) {
          if (size >= 0) used += size;
        }
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
  private mutate<T>(key: string, action: (path: string) => Promise<T>): Promise<T> {
    const path = this.path(key);
    const queueKey = key.toLowerCase().replace(/[. ]+$/, "");
    const previous = this.mutations.get(queueKey);
    const result = (async () => {
      await previous;
      await this.initialize();
      return action(path);
    })();
    const settled = result.then(() => {}, () => {});
    this.mutations.set(queueKey, settled);
    void settled.then(() => {
      if (this.mutations.get(queueKey) === settled) this.mutations.delete(queueKey);
    });
    return result;
  }

  /** Which keys are valid is `isSafeFsKey` (fs.ts), applied over every backend by
   *  `validatedFs`, and deliberately not duplicated here so targets cannot drift. This only
   *  adds containment: a key with a separator would escape `dir`. */
  private path(key: string): string {
    if (key === "" || key === "." || key === ".." || key.includes("/") || key.includes("\\")) {
      throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    }
    return `${this.dir}/${key}`;
  }

  private async names(withTemps = false): Promise<string[]> {
    const s = await this.files.list(this.dir);
    // An empty listing arrives as "", which must map to [], not split's [""].
    const names = s === "" ? [] : s.split("\n");
    return withTemps ? names : names.filter((n) => !n.startsWith(TMP_PREFIX));
  }

  async get(key: string): Promise<Uint8Array | null> {
    try {
      const b = await this.files.read(this.path(key), MAX_VALUE_BYTES);
      return b === null ? null : u8(b);
    } catch { return null; }
  }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    return this.mutate(key, async (path) => {
      const old = Math.max(0, await this.files.size(path));
      // Atomic but not fsynced: a lost block is re-fetched, a torn one would be served.
      await this.files.write(path, bytes);
      this.used += bytes.byteLength - old;
    });
  }
  async size(key: string): Promise<number> {
    try { return await this.files.size(this.path(key)); } catch { return -1; }
  }
  async list(prefix?: string): Promise<string[]> {
    try {
      const names = await this.names();
      return prefix ? names.filter((n) => n.startsWith(prefix)) : names;
    } catch { return []; }
  }
  async delete(key: string): Promise<boolean> {
    try {
      return await this.mutate(key, async (path) => {
        const old = Math.max(0, await this.files.size(path));
        if (!(await this.files.remove(path))) return false;
        this.used -= old;
        return true;
      });
    } catch { return false; }
  }
  async stat(): Promise<FsStat> {
    await this.initialize();
    const available = await this.files.available(this.dir);
    return { used: this.used, available: available < 0 ? FS_AVAILABLE_UNKNOWN : available };
  }
}
