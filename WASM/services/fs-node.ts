// Node's whole-file primitives (services/fs-files.ts `RawFiles`), and the `fs` store over
// them (exported as `seedkernel-wasm/fs-node`). Synchronous, as `RawFiles` is on every
// target: the Node platform's files, the operator's and the loader's slots included.

import { randomBytes } from "node:crypto";
import { closeSync, fstatSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, statfsSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import { FilesFs, type RawFiles } from "./fs-files.js";

/** The temp file an atomic write goes through before it is renamed over `path`: beside it,
 *  under the `~` that marks a platform's temp files. */
const tempBeside = (path: string): string =>
  join(dirname(path), `~${basename(path)}.${randomBytes(6).toString("hex")}`);

export const nodeRawFiles: RawFiles = {
  mkdir(dir) { mkdirSync(dir, { recursive: true }); },
  read(path, maxBytes) {
    let fd: number;
    try { fd = openSync(path, "r"); } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
      throw e;
    }
    try {
      if (fstatSync(fd).size > maxBytes) throw new Error(`fs: ${path} is larger than ${maxBytes} bytes`);
      const b = readFileSync(fd);
      // A plain Uint8Array view, so slice() copies (unlike Buffer's) without copying here.
      return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    } finally {
      closeSync(fd);
    }
  },
  write(path, bytes) {
    const tmp = tempBeside(path);
    try {
      writeFileSync(tmp, bytes, { mode: 0o600 });
      renameSync(tmp, path);
    } catch (err) {
      try { unlinkSync(tmp); } catch { /* never written */ }
      throw err;
    }
  },
  remove(path) {
    try { unlinkSync(path); return true; } catch { return false; }
  },
  size(path) {
    try {
      const s = statSync(path);
      return s.isFile() ? s.size : -1;
    } catch { return -1; }
  },
  list(dir) {
    return readdirSync(dir, { withFileTypes: true }).filter((e) => !e.isDirectory()).map((e) => e.name).join("\n");
  },
  available(dir) {
    try { const s = statfsSync(dir); return s.bavail * s.bsize; } catch { return -1; }
  },
};

/** The `fs` store in a directory on Node. */
export class NodeFs extends FilesFs {
  constructor(dir: string) { super(nodeRawFiles, dir); }
}
