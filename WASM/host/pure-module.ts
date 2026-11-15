// The §4 module ABI, once for every target: what a private module must export, and one
// call through its scratch window. Self-contained, with no imports and nothing captured
// from this file, because the JS targets run it inside each module's worker by its source
// text (module-table.ts); the native target runs it in the host realm over the engine
// table (platform.ts).

/** What the ABI needs of one module instance. */
export interface ModuleView {
  /** The `handle` export, or undefined when there is none. Its answer is the response
   *  length, or anything else for a failure. */
  handle: ((len: number) => unknown) | undefined;
  /** An exported global's value, or null when there is none by that name. */
  global(name: string): number | null;
  /** Linear memory in bytes, or a negative number when the module exports none. */
  memoryBytes(): number;
  read(ptr: number, len: number): Uint8Array;
  write(ptr: number, bytes: Uint8Array): void;
  /** Zero `len` bytes at `ptr`. */
  wipe(ptr: number, len: number): void;
}

/** A module checked against §4 (§4.1): it exports `memory`, a `scratch` offset and
 *  `handle`, and reserves `scratchSize` bytes at the offset, at least `scratchDefault`
 *  (the default when it declares none), inside its memory. Throws what is wrong. A call
 *  writes the request at the offset, runs `handle(length)`, and reads the response back
 *  from the same place, answering null when it is too large or `handle` answers no valid
 *  length. Both are wiped afterwards, so neither lingers in a long-lived instance. A throw
 *  from `handle` (a trap) is the caller's. */
export function scratchModule(m: ModuleView, scratchDefault: number):
  { size: number; call(payload: Uint8Array): Uint8Array | null } {
  const memory = m.memoryBytes();
  if (memory < 0) throw new Error("module missing export: memory");
  const scratch = m.global("scratch");
  if (scratch === null) throw new Error("module missing export: scratch");
  const handle = m.handle;
  if (typeof handle !== "function") throw new Error("module missing export: handle");
  const declared = m.global("scratchSize");
  if (declared !== null && !(declared >= scratchDefault)) {
    throw new Error(`invalid scratchSize ${declared} (must be >= ${scratchDefault})`);
  }
  const size = declared ?? scratchDefault;
  if (!(scratch > 0) || scratch + size > memory) {
    throw new Error(`scratch offset ${scratch} out of bounds (memory ${memory})`);
  }
  return {
    size,
    call(payload) {
      if (payload.length > size) return null;
      let wipe = payload.length;
      try {
        m.write(scratch, payload);
        const len = handle(payload.length);
        if (typeof len !== "number" || !(len >= 0 && len <= size)) return null;
        wipe = Math.max(wipe, len);
        return m.read(scratch, len);
      } finally {
        try { m.wipe(scratch, wipe); } catch { /* a trapped or closed instance */ }
      }
    },
  };
}

/** What `hostCryptoImports` needs of node:crypto. */
interface NodeCipher {
  setAAD(ad: Uint8Array): unknown;
  setAuthTag(tag: Uint8Array): unknown;
  getAuthTag(): Uint8Array;
  setAutoPadding(on: boolean): unknown;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
}
interface NodeCrypto {
  createCipheriv(alg: string, key: Uint8Array, iv: Uint8Array | null): NodeCipher;
  createDecipheriv(alg: string, key: Uint8Array, iv: Uint8Array): NodeCipher;
  createHash(alg: string): { update(data: Uint8Array): { digest(): Uint8Array } };
}

/** The `host_crypto` imports (wasm-limits.ts `MODULE_IMPORTS`) by node:crypto, on the
 *  module's memory, which `memory` answers once the instance exists. Native answers the
 *  same imports in Go (native/hostcrypto.go). */
export function hostCryptoImports(crypto: NodeCrypto, memory: () => WebAssembly.Memory):
  { host_crypto: Record<string, (...args: number[]) => number | void> } {
  const at = (ptr: number, n: number) => new Uint8Array(memory().buffer, ptr, n);
  // The last few header-protection keys' ECB ciphers, as native keeps its AES
  // (hostcrypto.go `aesKeys`): making one is most of what a block costs here, and a
  // connection masks every packet under one of two keys. GCM takes its nonce at creation,
  // so it has nothing to keep. The helpers are in here, since the module worker gets this
  // function as source (module-table.ts).
  const ecb: { key: Uint8Array; c: NodeCipher }[] = [];
  let nextEcb = 0;
  const sameKey = (a: Uint8Array, b: Uint8Array) => {
    for (let i = 0; i < 32; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  };
  const ecbFor = (key: Uint8Array): NodeCipher => {
    for (const e of ecb) {
      if (sameKey(e.key, key)) return e.c;
    }
    const c = crypto.createCipheriv("aes-256-ecb", key, null);
    c.setAutoPadding(false);
    ecb[nextEcb] = { key: key.slice(), c };
    nextEcb = (nextEcb + 1) % 4;
    return c;
  };
  return {
    host_crypto: {
      // (dest, key, pt, n, nonce, aad, alen): dest gets n + 16 bytes.
      seal(dest, key, pt, n, nonce, aad, alen) {
        const c = crypto.createCipheriv("aes-256-gcm", at(key, 32), at(nonce, 12));
        c.setAAD(at(aad, alen));
        const ct = c.update(at(pt, n));
        c.final();
        at(dest, n).set(ct);
        at(dest + n, 16).set(c.getAuthTag());
      },
      // (dest, key, ct, n >= 16, nonce, aad, alen) -> 0, or 1 for a bad tag.
      open(dest, key, ct, n, nonce, aad, alen) {
        const d = crypto.createDecipheriv("aes-256-gcm", at(key, 32), at(nonce, 12));
        d.setAAD(at(aad, alen));
        d.setAuthTag(at(ct + n - 16, 16));
        const pt = d.update(at(ct, n - 16));
        try { d.final(); } catch { return 1; }
        at(dest, n - 16).set(pt);
        return 0;
      },
      // (dest, key, in): one AES-256 block.
      block(dest, key, input) {
        at(dest, 16).set(ecbFor(at(key, 32)).update(at(input, 16)));
      },
      // (dest, msg, n): 32 bytes of SHA-256.
      sha256(dest, msg, n) {
        at(dest, 32).set(crypto.createHash("sha256").update(at(msg, n)).digest());
      },
    },
  };
}

/** AssemblyScript's three runtime shims, the same on every target (the other imports a
 *  module may make are the platform's crypto, wasm-limits.ts `MODULE_IMPORTS`).
 *  `abort` traps (a module calls it where it found itself broken, §4.2), `seed` is a
 *  constant (a pure transform reads no clock) and `trace` drops its arguments. */
export function moduleShims(): { env: Record<string, (...args: number[]) => number | void> } {
  return {
    env: {
      abort: (_msg: number, _file: number, line: number, col: number) => {
        throw new Error("module abort at " + line + ":" + col);
      },
      seed: () => 0,
      trace: () => {},
    },
  };
}
