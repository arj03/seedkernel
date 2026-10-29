// The in-memory `Fs` backend: portable, for tests and ephemeral nodes. It is the shared
// store (fs-files.ts) over whole files held in a map, so it keeps the rules every other
// target's store keeps. The per-app key rule is applied above it (`validatedFs`, fs.ts), so
// what an app can reach does not depend on the backend.

import { FilesFs, type RawFiles } from "./fs-files.js";

/** The in-memory backend's total quota, so puts cannot grow process memory without
 *  bound, and its entry quota, since an empty value holds memory too. */
export const DEFAULT_MEMORY_FS_MAX_BYTES = 64 * 1024 * 1024;
export const DEFAULT_MEMORY_FS_MAX_ENTRIES = 1 << 16;

/** Whole files in a map. A write past either quota is refused as a full disk refuses one,
 *  before anything changes. Files are stored and read as copies, so callers can reuse
 *  their buffers. */
export function memoryRawFiles(maxBytes = DEFAULT_MEMORY_FS_MAX_BYTES, maxEntries = DEFAULT_MEMORY_FS_MAX_ENTRIES): RawFiles {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || !Number.isSafeInteger(maxEntries) || maxEntries < 0) {
    throw new Error("memory-fs: invalid quota");
  }
  const files = new Map<string, Uint8Array>();
  let used = 0;
  return {
    mkdir() {},
    read(path, max) {
      const f = files.get(path);
      if (f && f.length > max) throw new Error(`memory-fs: ${path} is larger than ${max} bytes`);
      return f ? f.slice() : null;
    },
    write(path, bytes) {
      const previous = files.get(path);
      if (!previous && files.size >= maxEntries) throw new Error(`memory-fs: entry quota exceeded (cap ${maxEntries})`);
      const next = used - (previous?.length ?? 0) + bytes.length;
      if (next > maxBytes) throw new Error(`memory-fs: byte quota exceeded (cap ${maxBytes})`);
      // `new Uint8Array`, because a Node Buffer's slice() aliases the caller's storage.
      files.set(path, new Uint8Array(bytes));
      used = next;
    },
    remove(path) {
      used -= files.get(path)?.length ?? 0;
      return files.delete(path);
    },
    size: (path) => files.get(path)?.length ?? -1,
    list: (dir) => [...files.keys()].filter((p) => p.startsWith(dir + "/")).map((p) => p.slice(dir.length + 1)).join("\n"),
    available: () => maxBytes - used,
  };
}

/** The `fs` store in memory. */
export class MemoryFs extends FilesFs {
  constructor(maxBytes?: number, maxEntries?: number) {
    super(memoryRawFiles(maxBytes, maxEntries), "memory");
  }
}
