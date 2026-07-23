// The host and the handler table it owns (README §3, §4).
//
// The kernel is a **contract, not an artifact**: the table (`handlers[name] → handler`),
// the pure-transform handler ABI (§4), and the `SetHandler` semantics (§3.1). Its whole
// implementation is the one `Map` below. §1's vision sentence — "installing a handler is
// nothing more than `handlers[name] = wasm_bytes`" — is literally this map, so there is no
// kernel module to instantiate, no handler-id indirection, and no second table to keep in
// sync with a first.
//
// A handler is a PURE TRANSFORM (§4): it exports `memory`, a `scratch` global, and
// `handle(input_len)`; the host stages input at `scratch`, calls `handle`, and reads the
// response back from `scratch`. Handlers import nothing — no kernel seam, no I/O, no
// callback — so the host is the sole orchestrator: it reaches a handler by name with
// `callHandler` (the counterpart a guest reaches through the cap-bridge's MODULE_CALL,
// README §12.2), and does all I/O and authorization itself. Every entry is an installed
// WASM handler: a bundle is the one way code arrives (§12.4), so the table holds one kind
// of thing and `callHandler` has one path through it.
//
// The table is the host's ONLY install state. There is no ownership register beside it,
// because a kernel name derives from its author's key (§5.1) — so who may bind a name is
// answered by the name, and nothing can fall out of step with the table. That is also why
// nothing here touches crypto: hashing belongs to the loader (`genesisHash`, bundle.ts),
// and this component is the `Map` §3 says it is.
//
// Authenticity is the transport's job (the AKE channel attributes every frame), not a
// per-message signature — so there is no signature wrapper and no signer scoping here.

// ─── handler routing ─────────────────────────────────────────────────────

// Default scratch size mirrored by the host — handlers must reserve at least
// this much I/O space at their `scratch` offset (README §4.1).
const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

/** What the table holds at one name: an instantiated WASM handler, reached by name
 *  through `callHandler`. */
interface WasmHandlerRef {
  memory: WebAssembly.Memory;
  scratch: number;
  scratchSize: number;
  handle: (input_len: number) => number;
}

export class KernelHost {
  /** The handler table (README §3). A name is bound exactly when it is a key here, so
   *  the §3.1 SetHandler / remove / resolve operations are `set` / `delete` / `get` and
   *  nothing else can disagree about what a name resolves to. */
  private readonly handlers = new Map<string, WasmHandlerRef>();

  // ─── installing WASM handlers ─────────────────────────────────────────

  /** Instantiate handler `wasmBytes` — compile, validate, check §4 exports — without
   *  binding to the handler table. Throws on any structural failure so the caller can
   *  collect all failures before any name is written (two-phase bundle install).
   *
   *  A handler is a pure transform: it imports only the AssemblyScript runtime shims
   *  (`env.*`) — no `kernel.*` seam — and exports `memory`, a `scratch` global, and
   *  `handle`. */
  instantiateWasm(wasmBytes: Uint8Array): WasmHandlerRef {
    if (wasmBytes.length === 0) throw new Error("kernel: empty wasm bytes");
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

  /** Bind an instantiated handler ref at `targetName`. Displaces whatever was at the
   *  name without ceremony — the admission policy already ran. */
  bindHandler(targetName: string, ref: WasmHandlerRef): void {
    if (targetName.length === 0) throw new Error("kernel: empty handler name");
    this.handlers.set(targetName, ref);
  }

  /** Release a handler ref that will never be bound (the bundle failed). JS GC
   *  reclaims abandoned WebAssembly instances on its own, so this is a no-op — but
   *  it satisfies the BundleHost contract so the JS/native implementations share
   *  one interface. */
  discardHandler(_ref: WasmHandlerRef): void {}

  /** Instantiate handler `wasmBytes` and bind them at `targetName` in one call
   *  (README §4, §12.4). Throws on any structural failure — matching the fail-loud
   *  posture everywhere else.
   *
   *  The §3.1 bind, and the loader's admission (`installBundle`, §12.4) is its
   *  only caller — the policy has already run by the time control reaches here. */
  installWasmHandler(targetName: string, wasmBytes: Uint8Array): void {
    const ref = this.instantiateWasm(wasmBytes);
    this.bindHandler(targetName, ref);
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** Invoke a handler by name with `payload`, returning its response bytes, or null if
   *  the name is unbound or the handler produced no response. This is the scratch-region
   *  contract (README §4): write input at the handler's scratch offset, call
   *  handle(input_len), read the response back from the same offset. The generic "run a
   *  transform" primitive: the host uses it directly, and a guest reaches it through the
   *  cap-bridge's MODULE_CALL (README §12.2). Handlers cannot call back, so there is no
   *  re-entrancy. */
  callHandler(name: string, payload: Uint8Array): Uint8Array | null {
    const w = this.handlers.get(name);
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

  /** Remove a handler, the `SetHandler(name, null)` case in §3.1 — and the loader's
   *  `remove(name)` revocation path (§12.5). It frees the name and nothing else: there is
   *  no side table to keep in step, and a freed name can only ever be re-occupied by the
   *  author whose key derives it (§5.1), so a removal can never hand a slot to anyone. */
  removeHandler(name: string): boolean {
    return this.handlers.delete(name);
  }

  /** True if a handler occupies `name` — the §3.1 resolve, as a predicate. A shell uses
   *  it to check that the modules it expects a bundle to have landed are bound. */
  isBound(name: string): boolean {
    return this.handlers.has(name);
  }
}
