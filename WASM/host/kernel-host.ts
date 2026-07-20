// Host driver that loads kernel.wasm and wires the modules around it.
//
// The kernel is a named table of PURE-TRANSFORM handlers (README §3, §4). A
// handler exports `memory`, a `scratch` global, and `handle(input_len)`; the host
// stages input at `scratch`, calls `handle`, and reads the response back from
// `scratch`. Handlers import nothing — there is no kernel.call, no caller, no
// signer, no envelope dispatch. The host is the orchestrator: it reaches a handler
// by name with `callHandler` (the counterpart a guest reaches through the
// cap-bridge's MODULE_CALL, README §12.2), and does all I/O and authorization
// itself. The loader's install records live here too (README §12.4): the host binds
// handlers, so it holds the `InstallRecords` store and forgets a slot's record when a
// raw SetHandler mutates it — the host powers admission needs (instantiating WASM
// handlers, genesis hashing, querying the table) are all its own methods.
//
// Authenticity is the transport's job now (the AKE channel attributes every
// frame), not a per-message signature — so there is no signature wrapper, no
// signer scoping, and no §8/§4.4 authority machinery in the kernel at all.

import { InstallRecords, type AdmitPolicy, type InstallRecord } from "./bundle.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

/** The genesis signature suite's algo_id (README §6.2) — the author algo recorded
 *  for a bundle module's install record. */
export const GENESIS_ALGO_ID = 0x0000;

export interface Signer {
  algoId: number;
  publicKey: Uint8Array;
}

export type Handler = (
  name: Uint8Array,
  payload: Uint8Array,
  host: KernelHost
) => Uint8Array | void | null;

// ─── kernel.wasm exports ─────────────────────────────────────────────────

interface KernelExports {
  memory: WebAssembly.Memory;
  alloc(size: number): number;
  dealloc(ptr: number): void;
  set_handler(namePtr: number, nameLen: number, handlerId: number): void;
  remove_handler(namePtr: number, nameLen: number): number;
  find_handler(namePtr: number, nameLen: number): number;
}

// ─── handler routing ─────────────────────────────────────────────────────

// Default scratch size mirrored by the host — handlers must reserve at least
// this much I/O space at their `scratch` offset (README §4.1).
const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

interface WasmHandlerRef {
  memory: WebAssembly.Memory;
  scratch: number;
  scratchSize: number;
  handle: (input_len: number) => number;
  exports: WebAssembly.Exports;
}

// Everything the host tracks about one handler, keyed by the kernel's handler id.
// The kernel owns the name → id table (its `find_handler` export is the one
// routing decision); the host owns only the per-id impl. Exactly one of
// `handler` / `wasm` is set: a host-JS handler or a dynamic WASM handler.
interface HandlerEntry {
  name: Uint8Array;
  handler: Handler | null;
  wasm: WasmHandlerRef | null;
}

export class KernelHost {
  private kernelExports!: KernelExports;
  private sodium!: Sodium;
  // Host-side handler state, keyed by the kernel's handler id. The kernel owns
  // the name → id table (find_handler); the host owns only per-id metadata.
  private entries = new Map<number, HandlerEntry>();
  private nextHandlerId = 1;
  // The loader's install records + admission step (README §12.4). Intrinsic to the host
  // (it binds handlers), so a raw register/removeHandler can forget a stale record. No
  // admission policy is wired until setAdmitPolicy runs, so it refuses every bind by
  // default (deny-all, README §14).
  private readonly records = new InstallRecords(this);

  private constructor() {}

  /** Instantiate the kernel from in-memory bytes. The kernel alone is a usable
   *  host (§1): `register` and `callHandler` work with nothing else wired, and loading
   *  signed bundles is opt-in on top (wire an admission policy with setAdmitPolicy). The
   *  caller supplies the bytes and an initialized libsodium (SHA-3-256 for record
   *  hashing) —
   *  keeping the entry point free of Node- or browser-specific I/O is what lets the
   *  same host run in Node, browsers, Deno, Bun, etc. The thin entry points in
   *  `node.ts` / `browser.ts` package the loading dance for each platform. */
  static async load(
    kernelBytes: BufferSource,
    sodium: Sodium,
  ): Promise<KernelHost> {
    const host = new KernelHost();
    host.sodium = sodium;

    // ── load kernel.wasm ──────────────────────────────────────────────
    // The kernel imports nothing but the AssemblyScript runtime shims — it no
    // longer calls back into the host (there is no dispatch/invoke_handler path).
    const kernelImports: WebAssembly.Imports = {
      env: {
        abort: (_msgPtr: number, _filePtr: number, line: number, col: number) => {
          throw new Error(`kernel.wasm abort at ${line}:${col}`);
        },
        seed: () => Date.now(),
        trace: () => {},
      },
    };
    const kernelResult = await WebAssembly.instantiate(kernelBytes, kernelImports);
    host.kernelExports = kernelResult.instance.exports as unknown as KernelExports;

    return host;
  }

  // ─── kernel memory helpers ───────────────────────────────────────────

  private writeToKernel(data: Uint8Array): number {
    const ptr = this.kernelExports.alloc(data.length);
    new Uint8Array(this.kernelExports.memory.buffer, ptr, data.length).set(data);
    return ptr;
  }

  private readFromKernel(ptr: number, len: number): Uint8Array {
    return new Uint8Array(this.kernelExports.memory.buffer, ptr, len).slice();
  }

  /** Resolve the handler id bound to `name` via the kernel's find_handler
   *  export, or -1 if none. The single name → id lookup used by every host path
   *  so they can never disagree. */
  private findHandlerId(name: Uint8Array): number {
    const ptr = this.writeToKernel(name);
    try { return this.kernelExports.find_handler(ptr, name.length); }
    finally { this.kernelExports.dealloc(ptr); }
  }

  /** Bind `name` to `id` in the kernel table and record `entry` host-side,
   *  dropping whatever entry the name was previously bound to. Centralizes the
   *  "one name ⇒ one handler id" bookkeeping so register / _installWasmHandler
   *  can't leave a stale entry behind. */
  private bindHandler(name: Uint8Array, id: number, entry: HandlerEntry): void {
    const ptr = this.writeToKernel(name);
    let oldId: number;
    try {
      oldId = this.kernelExports.find_handler(ptr, name.length);
      this.kernelExports.set_handler(ptr, name.length, id);
    } finally {
      this.kernelExports.dealloc(ptr);
    }
    if (oldId >= 0 && oldId !== id) this.entries.delete(oldId);
    this.entries.set(id, entry);
  }

  // ─── invocation ──────────────────────────────────────────────────────

  /** Invoke the handler at `handlerId` with `payload`, returning its response
   *  bytes, or null if no response / no handler. For a WASM handler this is the
   *  scratch-region contract (README §4): write input at the handler's scratch
   *  offset, call handle(input_len), read the response from the same offset. */
  private _invokeHandlerGetResponse(
    handlerId: number,
    name: Uint8Array,
    payload: Uint8Array
  ): Uint8Array | null {
    const entry = this.entries.get(handlerId);
    if (!entry) return null;
    const wasm = entry.wasm;
    if (wasm) {
      if (payload.length > wasm.scratchSize) return null;
      new Uint8Array(wasm.memory.buffer, wasm.scratch, payload.length).set(payload);
      let responseLen: number;
      try { responseLen = wasm.handle(payload.length); }
      catch { return null; }
      // handle returns output_len ≥ 0 (§4): only a trap or a negative/oversized
      // length is a failure. Zero is a valid EMPTY response — return an empty
      // array for it, distinct from null (no handler / trap).
      if (responseLen < 0 || responseLen > wasm.scratchSize) return null;
      return new Uint8Array(wasm.memory.buffer, wasm.scratch, responseLen).slice();
    }
    const handler = entry.handler;
    if (handler) {
      try {
        const r = handler(name, payload, this);
        return r instanceof Uint8Array ? r : null;
      } catch {
        return null;
      }
    }
    return null;
  }

  // ─── installing WASM handlers ─────────────────────────────────────────

  /** Instantiate handler `wasmBytes` and bind them at `targetName` (README §4,
   *  §12.4). A handler is a pure transform: it imports only the AssemblyScript
   *  runtime shims (`env.*`) — no `kernel.*` seam — and exports `memory`, a
   *  `scratch` global, and `handle`. Returns false on any structural failure. */
  _installWasmHandler(targetName: Uint8Array, wasmBytes: Uint8Array): boolean {
    if (targetName.length === 0) return false;
    if (wasmBytes.length === 0) return false;

    const handlerId = this.nextHandlerId++;
    let instance: WebAssembly.Instance;
    try {
      const mod = new WebAssembly.Module(wasmBytes as BufferSource);
      const imports: WebAssembly.Imports = {
        env: {
          abort: (_m: number, _f: number, l: number, c: number) => {
            throw new Error(`dynamic handler abort at ${l}:${c}`);
          },
          seed: () => Date.now(),
          trace: () => {},
        },
      };
      instance = new WebAssembly.Instance(mod, imports);
    } catch {
      return false;
    }
    const exps = instance.exports as {
      memory?: WebAssembly.Memory;
      scratch?: WebAssembly.Global;
      scratchSize?: WebAssembly.Global;
      handle?: (input_len: number) => number;
    };
    if (!exps.memory || !(exps.scratch instanceof WebAssembly.Global) || typeof exps.handle !== "function") return false;
    const scratchOffset = exps.scratch.value as number;
    if (typeof scratchOffset !== "number" || scratchOffset <= 0 || scratchOffset + DEFAULT_SCRATCH_SIZE > exps.memory.buffer.byteLength) return false;
    // A handler may OPTIONALLY export `scratchSize` to declare a bigger I/O region
    // than the 128 KB default (README §4.1). Honor it only when it names real,
    // in-bounds memory the handler reserved past `scratch`; never shrink below the
    // default.
    let scratchSize = DEFAULT_SCRATCH_SIZE;
    if (exps.scratchSize instanceof WebAssembly.Global) {
      const declared = exps.scratchSize.value as number;
      if (typeof declared === "number" && declared >= DEFAULT_SCRATCH_SIZE &&
          scratchOffset + declared <= exps.memory.buffer.byteLength) {
        scratchSize = declared;
      }
    }

    // SetHandler is unconditional at the kernel level — replace whatever is
    // there (bindHandler drops the displaced id's host entry). The admission
    // policy was applied before this method was called.
    this.bindHandler(targetName, handlerId, {
      name: targetName.slice(),
      handler: null,
      wasm: {
        memory: exps.memory,
        scratch: scratchOffset,
        scratchSize,
        handle: exps.handle,
        exports: instance.exports,
      },
    });

    return true;
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** Call a named export on a dynamic WASM handler, staging `payload` in
   *  scratch first. Returns the export's i32 return value or null on failure.
   *  An export taking no arguments is reached with an empty payload. */
  callDynamicExport(
    name: Uint8Array,
    exportName: string,
    payload: Uint8Array,
  ): number | null | undefined {
    const hid = this.findHandlerId(name);
    if (hid < 0) return null;
    const wasm = this.entries.get(hid)?.wasm;
    if (!wasm) return null;
    const fn = (wasm.exports as { [k: string]: unknown })[exportName];
    if (typeof fn !== "function") return null;
    if (payload.length > wasm.scratchSize) return null;
    new Uint8Array(wasm.memory.buffer, wasm.scratch, payload.length).set(payload);
    return (fn as (n: number) => number)(payload.length);
  }

  /** Invoke a handler by name with `payload`, returning its response bytes (the
   *  standard `handle` scratch ABI), or null if the name is unbound or the handler
   *  produced no response. The generic "run a transform" primitive: the host uses
   *  it directly, and a guest reaches it through the cap-bridge's MODULE_CALL
   *  (README §12.2). Handlers cannot call back, so there is no re-entrancy. */
  callHandler(name: Uint8Array, payload: Uint8Array): Uint8Array | null {
    const hid = this.findHandlerId(name);
    if (hid < 0) return null;
    return this._invokeHandlerGetResponse(hid, name, payload);
  }

  /** Register a host-side handler (a JS closure bound at `name`). Returns the
   *  assigned id. Reachable exactly like a WASM handler — by name through
   *  `callHandler` — since the kernel table is indifferent to the impl. */
  register(name: Uint8Array, handler: Handler): number {
    const id = this.nextHandlerId++;
    this.bindHandler(name, id, {
      name: name.slice(),
      handler,
      wasm: null,
    });
    this.records.forget(name);
    return id;
  }

  /** Wire the admission policy the loader gates bundle modules with (README §12.5).
   *  Null (the default) refuses every bind, so a host that never calls this loads no
   *  app at all — deny-all (README §14). */
  setAdmitPolicy(admit: AdmitPolicy | null): void {
    this.records.setPolicy(admit);
  }

  /** Read-only access to the install record at `name`, or null. Host-side read of the
   *  loader's records (README §12.4) — there is no wire query. */
  lookupInstall(name: Uint8Array): InstallRecord | null {
    return this.records.lookup(name);
  }

  /** Admit a bundle module under its manifest-declared kernel name (README §12.4). The
   *  signed manifest already authenticated the coherent set and pinned each module's
   *  content hash, so the loader admits verified bytes here — bundles are the only way
   *  code arrives. The record's author is the manifest `authorPubKey` (an Ed25519 genesis
   *  key, §12.4), gated by the admission policy. Returns true on success, false if no
   *  policy is wired or it refuses. The bundle loader calls this once per verified module. */
  installBundleModule(name: Uint8Array, wasm: Uint8Array, authorPubKey: Uint8Array): boolean {
    return this.records.admit(name, wasm, { algoId: GENESIS_ALGO_ID, publicKey: authorPubKey });
  }

  /** Remove a handler, the `SetHandler(name, null)` case in §3.1 — and the loader's
   *  `remove(name)` revocation path (§12.5): it clears the slot's install record too, so
   *  the same key cannot later be misattributed onto brand-new bytes. */
  removeHandler(name: Uint8Array): boolean {
    const ptr = this.writeToKernel(name);
    try {
      const id = this.kernelExports.find_handler(ptr, name.length);
      const ok = this.kernelExports.remove_handler(ptr, name.length) === 1;
      if (ok) {
        if (id >= 0) this.entries.delete(id);
        this.records.forget(name);
      }
      return ok;
    } finally { this.kernelExports.dealloc(ptr); }
  }

  /** True if a handler occupies `name`. A bound name is exactly one the kernel's
   *  `find_handler` resolves, so this asks that rather than a second export. The loader's
   *  admission consults it (via `InstallRecords`) to refuse overlaying a hand-seeded slot. */
  isRegistered(name: Uint8Array): boolean {
    return this.findHandlerId(name) >= 0;
  }

  /** A bootstrap handler name (README §5.1): the literal-ASCII
   *  `"seedkernel.bootstrap.v1:" + canonical`. Bootstrap names are plain ASCII,
   *  not genesis-hash-derived — so names read plainly in logs. */
  deriveBootstrapName(canonical: string): Uint8Array {
    return new TextEncoder().encode("seedkernel.bootstrap.v1:" + canonical);
  }

  /** Hash the raw bytes of `data` with the genesis suite (SHA-3-256). Used by the loader's
   *  admission to compute a module's install-record `bytesHash` (§12.4), and exposed so
   *  deployers can compute the same hash off-line for policy allowlists. */
  genesisHash(data: Uint8Array): Uint8Array {
    return this.sodium.crypto_hash_sha3256(data);
  }

  /** Derive a deterministic name as `SHA-3-256(canonical || authorPubKey)`. Useful
   *  for deployer policies that want author-scoped names so two parties can each
   *  hold their own `chat` without conflict (§5.1). The kernel is indifferent to
   *  derivation — this is just a convenience. */
  deriveScopedName(canonical: string, authorPubKey: Uint8Array): Uint8Array {
    const nameBytes = new TextEncoder().encode(canonical);
    const buf = new Uint8Array(nameBytes.length + authorPubKey.length);
    buf.set(nameBytes, 0);
    buf.set(authorPubKey, nameBytes.length);
    return this.sodium.crypto_hash_sha3256(buf);
  }
}
