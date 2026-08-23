// `fs` (§12.1): raw bytes under an opaque flat key. Content-addressing and quota are
// app policy. Keys are filenames on both backends — charset in §16.1.

export interface FsStat {
  /** Total bytes stored across all keys (best-effort). */
  used: number;
  /** Real free space where the platform exposes it, else `FS_AVAILABLE_UNKNOWN`. */
  available: number;
}

/** Sentinel when the backend cannot ask the OS for free space. */
export const FS_AVAILABLE_UNKNOWN = Number.MAX_SAFE_INTEGER;

/** Storage seam. Every method is async: IndexedDB/OPFS cannot be sync, so a sync shape
 *  would drop the browser. */
export interface Fs {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, bytes: Uint8Array): Promise<void>;
  /** Byte length, or -1 if absent — existence is `size ≥ 0`; there is no `has`. */
  size(key: string): Promise<number>;
  list(prefix?: string): Promise<string[]>;
  /** true if a value was removed, false if the key was already absent. */
  delete(key: string): Promise<boolean>;
  stat(): Promise<FsStat>;
}

// Key charset is a consensus predicate (§16.1), applied once in shared JS.

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

/** Whether `scope` — the host-derived prefix an app's keys live under (shell-core
 *  `scopedFs`) — is representable as the head of every key it will ever reach. The
 *  charset only: a scope is not a whole key, so the bare-dot and device-name cases
 *  (which are about a complete name) do not apply to it. */
export function isSafeFsScope(scope: string): boolean {
  return SAFE_CHARS.test(scope);
}
