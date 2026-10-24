// The `fs` store over raw files (§12.1): one flat file per key under a directory, the same
// on every target. A platform supplies only whole-file primitives (`RawFiles`); the key
// store above them (space accounting, crash-temp cleanup) is here.

import type { Fs, FsStat } from "./fs.js";
import { FS_AVAILABLE_UNKNOWN } from "./fs.js";
import { u8, type Bytes } from "./util.js";

/** Whole files by path, as a platform offers them (host/abi.ts `PlatformFs`). Synchronous:
 *  the freshness marks are written inside install's commit window, which cannot await. */
export interface RawFiles {
  /** Create a directory and its parents. */
  mkdir(dir: string): void;
  /** A whole file, or `null` when it is absent. One larger than `maxBytes`, or one that
   *  cannot be read, throws. */
  read(path: string, maxBytes: number): Bytes | null;
  /** Write a whole file atomically and readable by this user alone, through a sibling temp
   *  file whose name starts with `~`; a crash can leave that file behind. */
  write(path: string, bytes: Uint8Array): void;
  /** false when there was nothing to remove. */
  remove(path: string): boolean;
  /** A regular file's size, or -1 when there is none. */
  size(path: string): number;
  /** The names in a directory, `\n`-joined. */
  list(dir: string): string;
  /** Free bytes on the directory's volume, or -1 when the platform cannot tell. */
  available(dir: string): number;
}

/** Marks a platform's temp files; `~` is outside the key charset. */
const TMP_PREFIX = "~";

/** No value is larger than one fs/put can carry (host/wasm-limits.ts
 *  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES), so a bigger file planted in the store is never
 *  read into memory. */
const MAX_VALUE_BYTES = 16 << 20;

export class FilesFs implements Fs {
  /** Bytes stored, -1 until the first scan. */
  private used = -1;

  constructor(private readonly files: RawFiles, private readonly dir: string) {}

  /** The directory, then one scan of it, before the first mutation or `stat`, which also
   *  reclaims the temp files a crash left behind. This instance assumes it is the only
   *  writer to its directory; reopen it to pick up outside changes. A failed scan is tried
   *  again on the next call. */
  private scan(): void {
    if (this.used >= 0) return;
    this.files.mkdir(this.dir);
    let used = 0;
    for (const n of this.names(true)) {
      if (n.startsWith(TMP_PREFIX)) this.files.remove(this.path(n));
      else used += Math.max(0, this.files.size(this.path(n)));
    }
    this.used = used;
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

  private names(withTemps = false): string[] {
    const s = this.files.list(this.dir);
    // An empty listing arrives as "", which must map to [], not split's [""].
    const names = s === "" ? [] : s.split("\n");
    return withTemps ? names : names.filter((n) => !n.startsWith(TMP_PREFIX));
  }

  // `async`, so a failure is a rejection on this seam, as `Fs` promises.
  async get(key: string): Promise<Uint8Array | null> {
    try {
      const b = this.files.read(this.path(key), MAX_VALUE_BYTES);
      return b === null ? null : u8(b);
    } catch { return null; }
  }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    const path = this.path(key);
    this.scan();
    const old = Math.max(0, this.files.size(path));
    // Atomic but not fsynced: a lost block is re-fetched, a torn one would be served.
    this.files.write(path, bytes);
    this.used += bytes.byteLength - old;
  }
  async size(key: string): Promise<number> {
    try { return this.files.size(this.path(key)); } catch { return -1; }
  }
  async list(prefix?: string): Promise<string[]> {
    try {
      const names = this.names();
      return prefix ? names.filter((n) => n.startsWith(prefix)) : names;
    } catch { return []; }
  }
  async delete(key: string): Promise<boolean> {
    try {
      const path = this.path(key);
      this.scan();
      const old = Math.max(0, this.files.size(path));
      if (!this.files.remove(path)) return false;
      this.used -= old;
      return true;
    } catch { return false; }
  }
  async stat(): Promise<FsStat> {
    this.scan();
    const available = this.files.available(this.dir);
    return { used: this.used, available: available < 0 ? FS_AVAILABLE_UNKNOWN : available };
  }
}
