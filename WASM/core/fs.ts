// The `fs.*` capability (exported as `seedkernel-wasm/fs`): raw bytes under an opaque,
// flat key — the storage-side twin of the raw net capability. The host knows nothing about
// content-addressing, descriptors or quota; those are app policy layered on top. Only real
// platform conditions surface: a full disk makes `put` throw, and `stat` reports what the
// backend can see.
//
// Keys are flat, not POSIX paths (see the key rule below).

export interface FsStat {
  /** Total bytes stored across all keys (best-effort). */
  used: number;
  /** Bytes the backend believes are still writable — real free space where the
   *  platform exposes it, otherwise a large sentinel. */
  available: number;
}

/** The `available` sentinel a backend reports when it cannot ask the OS for free space — a
 *  large number that never reads as "nearly full". Part of the seam rather than a
 *  per-backend choice, so a guest sizing its writes against `stat()` sees the same answer
 *  whatever the backend is. */
export const FS_AVAILABLE_UNKNOWN = Number.MAX_SAFE_INTEGER;

/** The storage seam. **Every method is async**, as a property of the seam rather than of
 *  any backend: a synchronous `get` is a shape no browser backend can implement (IndexedDB
 *  is async by construction, OPFS is sync only inside a Worker), so a sync seam would make
 *  the browser the one target that could not carry `fs`. A genuinely synchronous backend
 *  (`MemoryFs`) returns a resolved promise and costs a microtask.
 *
 *  ABI-visible: the `fs/*` names round-trip (§12.2), so a guest reads them with `await`.
 *  Which side of that line an op sits on is what `guest.abi` versions. */
export interface Fs {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, bytes: Uint8Array): Promise<void>;
  /** Byte length of the value under `key`, or -1 if absent. Existence is `size ≥ 0`
   *  (there is no separate `has`); also lets a policy layer rebuild an index without
   *  reading every value back. */
  size(key: string): Promise<number>;
  list(prefix?: string): Promise<string[]>;
  /** true if a value was removed, false if the key was already absent. */
  delete(key: string): Promise<boolean>;
  stat(): Promise<FsStat>;
}

// ─── what a key may be ───────────────────────────────────────────────────────
//
// A key is opaque to the runtime but not to the *medium*: both real backends map it to a
// filename verbatim, so it must be flat and safe — no separators, nothing that escapes a
// directory, nothing a platform resolves to something other than a file.
//
// It lives here because it is a consensus predicate, not a backend detail: which keys a
// node admits decides which blocks it stores and advertises, so two nodes that disagree
// about it disagree about their contents. Applied once, in shared JS, over whichever
// backend a target supplies (`validatedFs`, shell-core.ts); a backend's own path check is
// defence in depth rather than the thing relied on.

/** The key charset. Also the scope charset: a scope is a prefix of a key, so anything
 *  it could not be part of is not a scope either. */
const SAFE_CHARS = /^[A-Za-z0-9._-]+$/;

/** Names Windows resolves to a *device* before touching the filesystem: "CON"/"NUL"/"COM1"…
 *  reach the console, the null device or a serial port. Refused on every OS, because the
 *  key space must not depend on where a node runs. */
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
