// Node's whole-file primitives (services/fs-files.ts `RawFiles`), and the `fs` store over
// them (exported as `seedkernel-wasm/fs-node`). Truly async, so a node serving requests
// does not block its only thread on disk.

import { randomBytes } from "node:crypto";
import { mkdir, open, readdir, rename, stat, statfs, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { FilesFs, type RawFiles } from "./fs-files.js";

/** The temp file an atomic write goes through before it is renamed over `path`: beside it,
 *  under the `~` that marks a platform's temp files. */
export const tempBeside = (path: string): string =>
  join(dirname(path), `~${basename(path)}.${randomBytes(6).toString("hex")}`);

export const nodeRawFiles: RawFiles = {
  async mkdir(dir) { await mkdir(dir, { recursive: true }); },
  async read(path, maxBytes) {
    let f;
    try { f = await open(path, "r"); } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
      throw e;
    }
    try {
      const { size } = await f.stat();
      if (size > maxBytes) throw new Error(`fs: ${path} is larger than ${maxBytes} bytes`);
      const b = await f.readFile();
      // A plain Uint8Array view, so slice() copies (unlike Buffer's) without copying here.
      return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    } finally {
      await f.close();
    }
  },
  async write(path, bytes) {
    const tmp = tempBeside(path);
    try {
      await writeFile(tmp, bytes);
      await rename(tmp, path);
    } catch (err) {
      await unlink(tmp).catch(() => {});
      throw err;
    }
  },
  async remove(path) {
    try { await unlink(path); return true; } catch { return false; }
  },
  async size(path) {
    try {
      const s = await stat(path);
      return s.isFile() ? s.size : -1;
    } catch { return -1; }
  },
  async list(dir) {
    return (await readdir(dir, { withFileTypes: true })).filter((e) => !e.isDirectory()).map((e) => e.name).join("\n");
  },
  async available(dir) {
    try { const s = await statfs(dir); return s.bavail * s.bsize; } catch { return -1; }
  },
};

/** The `fs` store in a directory on Node. */
export class NodeFs extends FilesFs {
  constructor(dir: string) { super(nodeRawFiles, dir); }
}
