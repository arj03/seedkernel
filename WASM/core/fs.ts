// The `fs.*` capability (exported as `seedkernel-wasm/fs`, §12.1): raw bytes under an
// opaque, flat key — not a POSIX path (see the key rule below). Content-addressing,
// descriptors and quota are app policy; only real platform conditions surface, so a full
// disk makes `put` throw.

export interface FsStat {
  /** Total bytes stored across all keys (best-effort). */
  used: number;
  /** Real free space where the platform exposes it, else `FS_AVAILABLE_UNKNOWN`. */
  available: number;
}

/** The `available` sentinel for a backend that cannot ask the OS for free space — large
 *  enough never to read as "nearly full". Part of the seam rather than a per-backend
 *  choice, so a guest sizing its writes against `stat()` sees one answer. */
export const FS_AVAILABLE_UNKNOWN = Number.MAX_SAFE_INTEGER;

/** The storage seam. **Every method is async as a property of the seam rather than of any
 *  backend**: a synchronous `get` is a shape no browser backend can implement (IndexedDB
 *  is async by construction, OPFS sync only inside a Worker), so a sync seam would leave
 *  the browser the one target unable to carry `fs`. A synchronous backend (`MemoryFs`)
 *  resolves in a microtask, so a guest cannot work by accident on one backend and fail on
 *  the one it ships against. ABI-visible: the `fs/*` names round-trip and a guest awaits
 *  them (§12.2). */
export interface Fs {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, bytes: Uint8Array): Promise<void>;
  /** Byte length of the value under `key`, or -1 if absent — existence is `size ≥ 0`, and
   *  there is no separate `has`. */
  size(key: string): Promise<number>;
  list(prefix?: string): Promise<string[]>;
  /** true if a value was removed, false if the key was already absent. */
  delete(key: string): Promise<boolean>;
  stat(): Promise<FsStat>;
}

// ─── what a key may be ───────────────────────────────────────────────────────
//
// A key is opaque to the runtime but not to the *medium*: both real backends map it to a
// filename verbatim, so it must be flat and safe.
//
// It lives here because it is a consensus predicate, not a backend detail: which keys a
// node admits decides which blocks it stores, so two nodes disagreeing about it disagree
// about their contents. Applied once, in shared JS, over whichever backend a target
// supplies (`validatedFs`, shell-core.ts); a backend's own path check is defence in depth.

/** The key charset. Also the scope charset: a scope is a prefix of a key, so anything
 *  it could not be part of is not a scope either. */
const SAFE_CHARS = /^[A-Za-z0-9._-]+$/;

/** Names Windows resolves to a *device* before touching the filesystem. Refused on every
 *  OS, because the key space must not depend on where a node runs. */
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
