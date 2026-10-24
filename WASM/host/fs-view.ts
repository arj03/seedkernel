// One app's view of an fs backend (§12.2): the key rule, applied under that app's scope
// prefix. The rule itself (`isSafeFsKey`, services/fs.ts) is consensus; the host applies
// it over whatever backend the target supplies, so every host accepts the same keys and
// therefore stores and advertises the same contents.
import { isSafeFsKey, isSafeFsScope, type Fs } from "../services/fs.js";

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
