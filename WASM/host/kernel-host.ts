// The handler table (README §3, §4), as the JS targets implement it.
//
// **Host code, not core.** What is core about the kernel is the CONTRACT — the table,
// the §4 handler ABI, the bind/unbind semantics, and the §4.3 memory ceiling
// (core/wasm-limits.ts). This file is one platform's implementation of it, over
// `WebAssembly`; the native target's is a wazero map in Go behind its byte bridge
// (native/main.go), and neither is more canonical than the other. It sits with the
// other backends — `fs-node.ts`, `safe-js.ts` — for the same reason they do.
//
// The kernel is a **contract, not an artifact**: the table (`apps[appKey].get(module)`),
// the pure-transform handler ABI (§4), and the bind/unbind semantics (§3.1). Its whole
// implementation is the two `Map`s below. §1's vision sentence — "installing a handler is
// nothing more than `handlers[name] = wasm_bytes`" — is literally this, one level down:
// `apps[appKey].modules[name] = wasm_bytes`. It is the same sentence with the string codec
// taken out of the keys, so there is still no kernel module to instantiate, no handler-id
// indirection, and no second table to keep in sync with a first.
//
// **Two levels, because there are two things.** An app is what installs, what a binding
// points at and what `revoke` removes; a module is what a call resolves. Encoding both
// into one string key — `"<author hex>:<app>:<module>"` — bought a flat map at the cost of
// a codec: a charset rule so the module half could not contain the separator, a
// fixed-width author half so the app half could, a prefix scan for the unbind, and an
// argument about why the author hex must not be truncated lest one author grind their way
// onto another's names. Every one of those defends a shared namespace, and there is no
// shared namespace: a guest reaches only its own app's modules, bindings point at app
// keys, and a kernel name never leaves the host (§5.1). The outer key IS the ownership,
// visible without parsing anything.
//
// A handler is a PURE TRANSFORM (§4): it exports `memory`, a `scratch` global, and
// `handle(input_len)`; the host stages input at `scratch`, calls `handle`, and reads the
// response back from `scratch`. Handlers import nothing — no kernel seam, no I/O, no
// callback — so the host is the sole orchestrator: it reaches a handler by name with
// `callModule` (the counterpart a guest reaches through the cap-bridge's module/call,
// README §12.2), and does all I/O and authorization itself. Every entry is an installed
// WASM handler: a bundle is the one way code arrives (§12.4), so the table holds one kind
// of thing and `callModule` has one path through it.
//
// The table is the host's ONLY install state. There is no ownership register beside it,
// because ownership is the outer key (§5.1) — so who may bind a module is answered by
// where it sits, and nothing can fall out of step with the table. That is also why
// nothing here touches crypto: hashing belongs to the loader (`genesisHash`, bundle.ts),
// and this component is the `Map` §3 says it is.
//
// Authenticity is the transport's job (the AKE channel attributes every frame), not a
// per-message signature — so there is no signature wrapper and no signer scoping here.

import { checkHandlerMemory, DEFAULT_MAX_HANDLER_MEMORY_BYTES, DEFAULT_SCRATCH_SIZE } from "../core/wasm-limits.js";

// ─── handler routing ─────────────────────────────────────────────────────

export interface KernelHostOptions {
  /** Ceiling on a handler's declared initial *and* maximum linear memory, in bytes.
   *  A module above it — or one declaring no maximum at all — is refused at install
   *  (§4.3). Defaults to the shared `DEFAULT_MAX_HANDLER_MEMORY_BYTES` that
   *  `installBundle` also applies; lower it to hold this host's direct installs to
   *  something tighter than the bundle path requires. */
  maxHandlerMemoryBytes?: number;
}

/** What the table holds at one name: an instantiated WASM handler, reached by name
 *  through `callModule`. */
interface WasmHandlerRef {
  memory: WebAssembly.Memory;
  scratch: number;
  scratchSize: number;
  handle: (input_len: number) => number;
}

export class KernelHost {
  /** The handler table (README §3): app key → that app's modules by logical name. A
   *  module is bound exactly when it is a key in its app's map, so the §3.1 bind /
   *  unbind / resolve operations are `set` / `delete` / `get` and nothing else can
   *  disagree about what resolves. */
  private readonly apps = new Map<string, Map<string, WasmHandlerRef>>();

  /** The §4.3 memory ceiling this host holds installs to. */
  private readonly maxHandlerMemoryBytes: number;

  constructor(opts: KernelHostOptions = {}) {
    this.maxHandlerMemoryBytes = opts.maxHandlerMemoryBytes ?? DEFAULT_MAX_HANDLER_MEMORY_BYTES;
  }

  // ─── installing WASM handlers ─────────────────────────────────────────

  /** Land an app's modules on the table, all or none (§3.1) — the one way code arrives,
   *  and the only mutating entry point besides `removeApp`.
   *
   *  Every module is instantiated and validated BEFORE anything is written, so a bundle
   *  whose third module is malformed leaves the table exactly as it was rather than
   *  half-replaced. Atomicity is now visible rather than argued: the app's whole module
   *  map is built first and then assigned under its key, so the commit is ONE assignment
   *  and there is no window in which some of an app's modules are the new version and
   *  the rest are the old.
   *
   *  A re-install REPLACES the app's map rather than merging into it, which is what a
   *  version of an app is: a bundle dropping a module from its manifest leaves nothing
   *  of the old one behind.
   *
   *  Instances abandoned by a failure need no explicit release here — JS reclaims an
   *  unreferenced `WebAssembly.Instance` on its own. A host whose instances are not
   *  garbage-collected frees them on this same path (native/main.go), which is exactly
   *  why the release is the host's business and not a step in the loader. */
  bindAll(appKey: string, mods: { name: string; wasm: Uint8Array }[]): void {
    if (appKey.length === 0) throw new Error("kernel: empty app key");
    const built = new Map<string, WasmHandlerRef>();
    for (const m of mods) {
      if (m.name.length === 0) throw new Error("kernel: empty module name");
      built.set(m.name, this.instantiate(m.wasm));
    }
    // Nothing above touched the table, and this cannot fail.
    this.apps.set(appKey, built);
  }

  /** Instantiate handler `wasmBytes` — compile, validate, check §4 exports — without
   *  binding to the handler table. Private: a ref that is not on the table is an
   *  intermediate of `bindAll`'s transaction and never something a caller holds.
   *
   *  A handler is a pure transform: it imports nothing from the runtime — no `kernel.*`
   *  seam, only its own language runtime's shims (`env.*`, §4.2) — and exports `memory`,
   *  a `scratch` global, and `handle`. */
  private instantiate(wasmBytes: Uint8Array): WasmHandlerRef {
    if (wasmBytes.length === 0) throw new Error("kernel: empty wasm bytes");
    // BEFORE instantiation, not after: `new WebAssembly.Instance` allocates the module's
    // declared initial memory, so a module asking for 4 GiB has already OOMed this host
    // by the time the export checks below could see it. Reading the limits off the bytes
    // is the only point at which the §4.3 memory residual can be refused (wasm-limits.ts,
    // which also refuses an imported or shared memory).
    checkHandlerMemory(wasmBytes, this.maxHandlerMemoryBytes);
    let instance: WebAssembly.Instance;
    try {
      const mod = new WebAssembly.Module(wasmBytes as BufferSource);
      // The three AssemblyScript runtime shims and nothing else — the same set every
      // other target resolves (native/main.go), so "does this module load" is never a
      // property of which target it landed on. All three are inert: `seed` is a constant
      // rather than `Date.now()`, because a pure transform is deterministic and reaches
      // no clock (§4.2) — a handler needing entropy takes it in its input — and `trace`
      // drops its arguments rather than writing them where anything could observe them,
      // so a handler's only effect stays the bytes it returns (§4.3).
      const imports: WebAssembly.Imports = {
        env: {
          abort: (_m: number, _f: number, l: number, c: number) => {
            throw new Error(`dynamic handler abort at ${l}:${c}`);
          },
          seed: () => 0,
          trace: () => {},
        },
      };
      instance = new WebAssembly.Instance(mod, imports);
    } catch (e) {
      throw new Error(`kernel: failed to instantiate wasm: ${(e as Error).message}`);
    }
    const exps = instance.exports as {
      memory?: WebAssembly.Memory;
      scratch?: WebAssembly.Global;
      scratchSize?: WebAssembly.Global;
      handle?: (input_len: number) => number;
    };
    if (!exps.memory) throw new Error("kernel: handler missing export: memory");
    if (!(exps.scratch instanceof WebAssembly.Global)) throw new Error("kernel: handler missing export: scratch");
    if (typeof exps.handle !== "function") throw new Error("kernel: handler missing export: handle");
    const scratchOffset = exps.scratch.value as number;
    if (typeof scratchOffset !== "number" || scratchOffset <= 0 || scratchOffset + DEFAULT_SCRATCH_SIZE > exps.memory.buffer.byteLength) {
      throw new Error(`kernel: scratch offset ${scratchOffset} out of bounds`);
    }
    let scratchSize = DEFAULT_SCRATCH_SIZE;
    if (exps.scratchSize instanceof WebAssembly.Global) {
      const declared = exps.scratchSize.value as number;
      if (typeof declared !== "number" || declared < DEFAULT_SCRATCH_SIZE) {
        throw new Error(`kernel: invalid scratchSize ${declared} (must be >= ${DEFAULT_SCRATCH_SIZE})`);
      }
      if (scratchOffset + declared > exps.memory.buffer.byteLength) {
        throw new Error(`kernel: scratchSize ${declared} overflows memory`);
      }
      scratchSize = declared;
    }
    return {
      memory: exps.memory,
      scratch: scratchOffset,
      scratchSize,
      handle: exps.handle,
    };
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** Invoke one app's module with `payload`, returning its response bytes, or null if
   *  nothing is bound there or the handler produced no response. This is the
   *  scratch-region contract (README §4): write input at the handler's scratch offset,
   *  call handle(input_len), read the response back from the same offset. The generic
   *  "run a transform" primitive: the host uses it directly, and a guest reaches it
   *  through the cap-bridge's module/call (README §12.2) — with the app key bound at
   *  bridge construction, so `module` is the LOGICAL name from the guest's own manifest
   *  and a guest cannot address another app's modules by naming one. Handlers cannot
   *  call back, so there is no re-entrancy. */
  callModule(appKey: string, module: string, payload: Uint8Array): Uint8Array | null {
    const w = this.apps.get(appKey)?.get(module);
    if (!w) return null;
    if (payload.length > w.scratchSize) return null;
    new Uint8Array(w.memory.buffer, w.scratch, payload.length).set(payload);
    let responseLen: number;
    try { responseLen = w.handle(payload.length); }
    catch { return null; }
    // handle returns output_len ≥ 0 (§4): only a trap or a negative/oversized length is a
    // failure. Zero is a valid EMPTY response — return an empty array for it, distinct
    // from null (no handler / trap).
    if (responseLen < 0 || responseLen > w.scratchSize) return null;
    return new Uint8Array(w.memory.buffer, w.scratch, responseLen).slice();
  }

  /** Drop an app and everything it landed, returning how many modules went — the §3.1
   *  unbind, and the whole of it. The unit is an APP, which is now simply the key: the
   *  shell's `uninstall` and `revoke` (§12.5) are the only callers, and both mean exactly
   *  this. Install and removal are visibly the same unit, so there is no asymmetry left
   *  to explain.
   *
   *  There is no single-module remove. Nothing wants one — a module is not a unit anything
   *  installs or revokes — and with modules living inside their app there is no shared
   *  namespace for a freed one to be contended for, so there is nothing to keep in step
   *  and no tombstone to leave behind. */
  removeApp(appKey: string): number {
    const mods = this.apps.get(appKey);
    if (!mods) return 0;
    this.apps.delete(appKey);
    return mods.size;
  }

  /** True if `module` is bound for `appKey` — the §3.1 resolve, as a predicate. A shell
   *  uses it to check that the modules it expects a bundle to have landed are bound. */
  isBound(appKey: string, module: string): boolean {
    return this.apps.get(appKey)?.has(module) ?? false;
  }
}
