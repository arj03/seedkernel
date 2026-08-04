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
 *  costs a microtask. The backends themselves are host code — this file is the seam they
 *  satisfy plus the scoping every host must apply over it, and nothing else.
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
// target supplies (`validatedFs`), and a backend's own path check is defence in depth
// rather than the thing being relied on.

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

/** Apply the key rule over a backend, once, for every target.
 *
 *  A rejected key **throws** rather than reading as absent. An unrepresentable key is a
 *  caller bug, and answering `null`/`-1`/`false` would hide it on a read while `put`
 *  failed anyway — so the one behaviour is the loud one, on every op that names a key.
 *  `list` is not one of them: its argument is a prefix, and the empty prefix ("every key
 *  I can see") is exactly the call a key rule would wrongly refuse. `stat` names nothing.
 *
 *  Wrapping happens where a backend enters the shell (`createShell`), so it sits UNDER
 *  `scopedFs` and therefore validates the composite `scope + key` a guest actually
 *  reaches — which is the string the medium sees. */
export function validatedFs(inner: Fs): Fs {
  const check = (key: string): string => {
    if (!isSafeFsKey(key)) throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    return key;
  };
  // `async` so a refusal is a REJECTION, like every other failure on this seam. A
  // synchronous throw would reach a caller that only attached `.catch` as an exception.
  return {
    async get(key) { return inner.get(check(key)); },
    async put(key, bytes) { return inner.put(check(key), bytes); },
    async size(key) { return inner.size(check(key)); },
    list: (prefix) => inner.list(prefix),
    async delete(key) { return inner.delete(check(key)); },
    stat: () => inner.stat(),
  };
}

/** Scope a backend to one app's private keyspace (README §12.2).
 *
 *  Without this, every app granted the `fs` domain shares one flat keyspace: `FS_LIST`
 *  with an empty prefix enumerates every key on the node, `FS_GET` reads any of them and
 *  `FS_DELETE` removes any of them. That is the one place the runtime's "ownership is
 *  structural" property (§5.1) did not hold — kernel *names* carry their author, so one
 *  app's modules are unreachable to another by construction, but fs *keys* carried
 *  nothing and were reachable to everyone. This closes that asymmetry the same way the
 *  names do: by derivation, not by a rule something has to enforce.
 *
 *  `scope` is an opaque prefix derived from the app key by `appScopeFor` (bundle.ts) —
 *  derived there rather than here because it needs a hash, and this module stays
 *  dependency-free. Two properties matter and both come from that derivation: it lies
 *  inside the backend's key charset, and it is fixed-length, so distinct scopes cannot
 *  overlap however an author names the app. (An app name may itself contain `:`, so a
 *  plain `appKey + separator` prefix would let app `x` key `y:z` collide with app `x:y`
 *  key `z` — and would be rejected by both backends anyway.)
 *
 *  `stat()` is deliberately NOT scoped — `used`/`available` describe the physical
 *  backend, and reporting a per-app figure for `available` would be a fiction. An app
 *  that wants its own footprint sums `size()` over its own `list()`, which is now
 *  exactly its own keys. */
export function scopedFs(inner: Fs, scope: string): Fs {
  // A scope prefix must survive the key rule above — it is the head of every key this
  // app will ever reach — so it is checked here, at construction, rather than on the
  // first `put`. The charset only: a scope is not a whole key, so the bare-dot and
  // device-name cases (which are about a complete name) do not apply to it.
  if (!SAFE_CHARS.test(scope)) throw new Error(`fs: unsafe scope ${JSON.stringify(scope)}`);
  const outward = (key: string): string => scope + key;
  return {
    get: (key) => inner.get(outward(key)),
    put: (key, bytes) => inner.put(outward(key), bytes),
    size: (key) => inner.size(outward(key)),
    // An absent prefix means "everything I can see", which is now everything in this
    // scope and nothing else. Keys come back stripped, so the guest only ever handles
    // the names it chose and the scope stays a host-side fact.
    list: async (prefix) => (await inner.list(outward(prefix ?? ""))).map((k) => k.slice(scope.length)),
    delete: (key) => inner.delete(outward(key)),
    stat: () => inner.stat(),
  };
}
