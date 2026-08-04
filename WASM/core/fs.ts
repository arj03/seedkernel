// The `fs.*` capability (exported as `seedkernel-wasm/fs`): raw bytes under an
// opaque, flat key. It is the storage-side twin of `net.*` (raw bytes to/from an
// opaque peer id) — see the runtime split, "raw-byte caps in the kernel,
// structure in modules". The kernel knows nothing about content-addressing,
// descriptors, or quota: those are app policy that an application layers on top
// (seedstore's FsBlobStore does exactly that). Only real platform conditions
// surface — a full disk makes `put` throw, and `stat` reports what the backend
// can see.
//
// Keys are opaque and flat (not POSIX paths). Backends may constrain the key
// charset to what maps safely onto their medium (NodeFs requires filesystem-safe
// names); seedstore's keys are hashes plus a short suffix, well within that.

export interface FsStat {
  /** Total bytes stored across all keys (best-effort). */
  used: number;
  /** Bytes the backend believes are still writable — real free space where the
   *  platform exposes it, otherwise a large sentinel. */
  available: number;
}

/** The storage seam. **Every method is async**, and that is a property of the seam
 *  rather than of any backend: a synchronous `get(key): Uint8Array | null` is a shape no
 *  browser backend can implement — IndexedDB is asynchronous by construction and OPFS is
 *  synchronous only inside a Worker — so a sync seam would have made the browser the one
 *  target that could not carry `fs`, which is core (README §1). A backend that genuinely
 *  is synchronous (`MemoryFs`, host/fs-memory.ts) returns an already-resolved promise and
 *  costs a microtask. The backends themselves are host code, as are the wrappers that
 *  apply the key rule over them (`validatedFs`/`scopedFs`, shell-core.ts) — this file is
 *  the seam they satisfy plus the consensus key rule, and nothing else.
 *
 *  It is ABI-visible: `FS_*` are round-tripping ops (§12.2), so a guest reads them with
 *  `await`. Which side of that line an op sits on is exactly what `guest.abi` versions, so
 *  a guest written against another shape is refused by name at load rather than handed a
 *  Promise where it expected bytes. */
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
// A key is opaque to the runtime but it is not opaque to the *medium*: both real
// backends map it to a filename verbatim, so it must be flat and safe — no separators,
// nothing that escapes a directory, nothing a platform resolves to something other
// than a file. seedstore's keys (hex block-ids plus a short suffix) satisfy this.
//
// **It lives here because it is a consensus predicate, not a backend detail.** Which
// keys a node admits decides which blocks it stores and advertises, so two nodes that
// disagree about it disagree about their contents — the same argument that keeps one
// ML-DSA verifier for all three targets (`pq.ts`). It was previously written twice, in
// `host/fs-node.ts` and again in `native/fs.go`, with a comment on each saying the two
// had to match. Now the rule is applied once, in shared JS, over whichever backend a
// target supplies (`validatedFs`, shell-core.ts), and a backend's own path check is
// defence in depth rather than the thing being relied on.

/** The key charset. Also the scope charset: a scope is a prefix of a key, so anything
 *  it could not be part of is not a scope either. */
const SAFE_CHARS = /^[A-Za-z0-9._-]+$/;

/** Names Windows resolves to a *device* before it ever touches the filesystem: opening
 *  "CON"/"NUL"/"COM1"… — with or without an extension — reaches the console, the null
 *  device or a serial port, not a file. Refused on every OS, not only Windows, because
 *  the key space must not depend on where a node runs. */
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
