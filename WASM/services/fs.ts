// `fs` (§12.1): raw bytes under an opaque flat key. Content addressing and quotas are
// app policy. Keys are filenames on both backends; the charset is in §16.1.
import { concatBytes, dec, EMPTY, ONE, ZERO, readU32BE, writeU32BE } from "../host/util.js";
import { OpArgs } from "../host/op-frame.js";
import type { ServiceHandlers } from "../host/guest-seam.js";

export interface FsStat {
  /** Total bytes stored across all keys (best-effort). */
  used: number;
  /** Real free space where the platform exposes it, else `FS_AVAILABLE_UNKNOWN`. */
  available: number;
}

/** Sentinel when the backend cannot ask the OS for free space. */
export const FS_AVAILABLE_UNKNOWN = Number.MAX_SAFE_INTEGER;

/** Storage seam. Synchronous, as the `RawFiles` under every backend is (fs-files.ts), so a
 *  guest's `fs/*` call is answered in the frame that asked (guest-seam.ts). A failure
 *  throws. */
export interface Fs {
  get(key: string): Uint8Array | null;
  put(key: string, bytes: Uint8Array): void;
  /** Byte length, or -1 if absent. Use `size >= 0` to test existence. */
  size(key: string): number;
  list(prefix?: string): string[];
  /** true if a value was removed, false if the key was already absent. */
  delete(key: string): boolean;
  stat(): FsStat;
}

// The key charset is consensus (§16.1), applied once in shared code.

/** The key charset. Also the scope charset. */
const SAFE_CHARS = /^[A-Za-z0-9._-]+$/;

/** Windows device names. Refused on every OS so the key space does not depend on the host. */
const RESERVED_DEVICE_NAMES = new Set<string>(["CON", "PRN", "AUX", "NUL"]);
for (let i = 0; i <= 9; i++) { // COM0/LPT0 are reserved on current Windows too
  RESERVED_DEVICE_NAMES.add("COM" + i);
  RESERVED_DEVICE_NAMES.add("LPT" + i);
}

/** Windows ignores the extension, so the stem before the first `.` decides it:
 *  "NUL.txt" is still NUL. */
function isReservedDeviceName(key: string): boolean {
  const dot = key.indexOf(".");
  return RESERVED_DEVICE_NAMES.has((dot >= 0 ? key.slice(0, dot) : key).toUpperCase());
}

/** Whether `key` is representable on every backend. The bare dot names are excluded
 *  explicitly: they are directory references, not files. */
export function isSafeFsKey(key: string): boolean {
  return key !== "." && key !== ".." && SAFE_CHARS.test(key) && !isReservedDeviceName(key);
}

/** Whether `scope`, the host-derived prefix of an app's keys (`scopedFs`), is valid as
 *  the start of every key. Charset only: the bare-dot and device-name rules apply to whole
 *  names, not prefixes. */
export function isSafeFsScope(scope: string): boolean {
  return SAFE_CHARS.test(scope);
}

// One app's view of a backend (§12.2): the key rule, applied under that app's scope prefix.
// The rule itself is consensus; the host applies it over whatever backend the target
// supplies, so every host accepts the same keys and therefore stores and advertises the
// same contents.

/** Apply the key rule over a backend. Rejected keys throw; `list` and `stat` are exempt.
 *  Sits under `scopedFs` so the full `scope + key` is checked. */
export function validatedFs(inner: Fs): Fs {
  const check = (key: string): string => {
    if (!isSafeFsKey(key)) throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    return key;
  };
  return {
    get: (key) => inner.get(check(key)),
    put: (key, bytes) => inner.put(check(key), bytes),
    size: (key) => inner.size(check(key)),
    list: (prefix) => inner.list(prefix),
    delete: (key) => inner.delete(check(key)),
    stat: () => inner.stat(),
  };
}

/** Scope a backend to one app's keyspace (§12.2). `scope` is `appScopeFor`'s
 *  fixed-length prefix. `stat()` is not scoped: it describes the physical backend. */
export function scopedFs(inner: Fs, scope: string): Fs {
  // Every key this app reaches starts with the scope, so check it once here. Charset
  // only (`isSafeFsScope`): the bare-dot and device-name rules apply to whole names, not
  // prefixes.
  if (!isSafeFsScope(scope)) throw new Error(`fs: unsafe scope ${JSON.stringify(scope)}`);
  const outward = (key: string): string => scope + key;
  return {
    get: (key) => inner.get(outward(key)),
    put: (key, bytes) => inner.put(outward(key), bytes),
    size: (key) => inner.size(outward(key)),
    // No prefix means everything in this scope. Keys come back with the scope stripped,
    // so the guest only sees names it chose.
    list: (prefix) => inner.list(outward(prefix ?? "")).map((k) => k.slice(scope.length)),
    delete: (key) => inner.delete(outward(key)),
    stat: () => inner.stat(),
  };
}

function u64be(value: number): Uint8Array {
  const out = new Uint8Array(8);
  writeU32BE(out, 0, Math.floor(value / 0x100000000));
  writeU32BE(out, 4, value >>> 0);
  return out;
}

/** The `fs` handlers over one app's scoped view. Synchronous like the store, so each
 *  answers inline. Views, not copies: the payload already belongs to this call, and
 *  backends copy (or write) before returning. */
export function fsService(fs: Fs): ServiceHandlers<"fs"> {
  return {
    "fs/get": (payload) => { const v = fs.get(dec.decode(payload)); return v ? concatBytes([ONE, v]) : ZERO; },
    "fs/put": (payload) => {
      const klen = readU32BE(payload, 0);
      fs.put(dec.decode(payload.subarray(4, 4 + klen)), payload.subarray(4 + klen));
      return EMPTY;
    },
    // -> [count u32]([len u32][key utf8])*
    "fs/list": (payload) => {
      const keys = fs.list(payload.length ? dec.decode(payload) : undefined);
      return keys.reduce((out, k) => out.text(k), new OpArgs().u32(keys.length)).build();
    },
    "fs/delete": (payload) => { fs.delete(dec.decode(payload)); return EMPTY; },
    // -> [size u32], all ones (-1) for absent.
    "fs/size": (payload) => new OpArgs().u32(fs.size(dec.decode(payload)) >>> 0).build(),
    "fs/stat": () => { const s = fs.stat(); return concatBytes([u64be(s.used), u64be(s.available)]); },
  };
}
