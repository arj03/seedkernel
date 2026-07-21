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
// README §12.2), and does all I/O and authorization itself. The loader's install records
// live here too (README §12.4): the host binds handlers, so it holds the `InstallRecords`
// store and forgets a slot's record when a raw SetHandler mutates it.
//
// Authenticity is the transport's job (the AKE channel attributes every frame), not a
// per-message signature — so there is no signature wrapper and no signer scoping here.

import { InstallRecords, type AdmitPolicy, type InstallRecord } from "./bundle.js";
import { toHex } from "./util.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

export type Handler = (
  name: string,
  payload: Uint8Array,
  host: KernelHost
) => Uint8Array | void | null;

// ─── handler routing ─────────────────────────────────────────────────────

// Default scratch size mirrored by the host — handlers must reserve at least
// this much I/O space at their `scratch` offset (README §4.1).
const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

interface WasmHandlerRef {
  memory: WebAssembly.Memory;
  scratch: number;
  scratchSize: number;
  handle: (input_len: number) => number;
}

/** What the table holds at one name. Exactly one of `handler` / `wasm` is set: a
 *  host-JS handler or an installed WASM handler. The table is indifferent to which —
 *  both are reached the same way, by name through `callHandler`. */
interface HandlerEntry {
  handler: Handler | null;
  wasm: WasmHandlerRef | null;
}

export class KernelHost {
  /** The handler table (README §3). A name is bound exactly when it is a key here, so
   *  the §3.1 SetHandler / remove / resolve operations are `set` / `delete` / `get` and
   *  nothing else can disagree about what a name resolves to. */
  private readonly handlers = new Map<string, HandlerEntry>();
  private readonly sodium: Sodium;
  // The loader's install records + admission step (README §12.4). Intrinsic to the host
  // (it binds handlers), so a raw register/removeHandler can forget a stale record. No
  // admission policy is wired until setAdmitPolicy runs, so it refuses every bind by
  // default (deny-all, README §14).
  private readonly records = new InstallRecords(this);

  /** The host needs nothing but a hash to stand up: hand it an initialized libsodium
   *  (BLAKE2b-256 for content hashing) and the table is live — `register` and
   *  `callHandler` work with nothing else wired (§1), and loading signed bundles is
   *  opt-in on top (wire an admission policy with `setAdmitPolicy`). Keeping the
   *  constructor free of Node- or browser-specific I/O is what lets the same host run in
   *  Node, browsers, Deno, Bun and QuickJS; the thin entry points in `node.ts` /
   *  `browser.ts` package readying sodium for each platform. */
  constructor(sodium: Sodium) {
    this.sodium = sodium;
  }

  // ─── invocation ──────────────────────────────────────────────────────

  /** Run `entry` with `payload`, returning its response bytes, or null if it produced
   *  none. For a WASM handler this is the scratch-region contract (README §4): write
   *  input at the handler's scratch offset, call handle(input_len), read the response
   *  from the same offset. */
  private invoke(
    entry: HandlerEntry,
    name: string,
    payload: Uint8Array
  ): Uint8Array | null {
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
  _installWasmHandler(targetName: string, wasmBytes: Uint8Array): boolean {
    if (targetName.length === 0) return false;
    if (wasmBytes.length === 0) return false;

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

    // SetHandler is unconditional at the table level — replace whatever is there. The
    // admission policy was applied before this method was called. The displaced entry
    // is simply dropped: the instance it held is unreachable and collectable.
    this.handlers.set(targetName, {
      handler: null,
      wasm: {
        memory: exps.memory,
        scratch: scratchOffset,
        scratchSize,
        handle: exps.handle,
      },
    });

    return true;
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** Invoke a handler by name with `payload`, returning its response bytes (the
   *  standard `handle` scratch ABI), or null if the name is unbound or the handler
   *  produced no response. The generic "run a transform" primitive: the host uses
   *  it directly, and a guest reaches it through the cap-bridge's MODULE_CALL
   *  (README §12.2). Handlers cannot call back, so there is no re-entrancy. */
  callHandler(name: string, payload: Uint8Array): Uint8Array | null {
    const entry = this.handlers.get(name);
    return entry ? this.invoke(entry, name, payload) : null;
  }

  /** Register a host-side handler (a JS closure bound at `name`) — the `SetHandler`
   *  path of §3.1. Reachable exactly like a WASM handler, by name through
   *  `callHandler`, since the table is indifferent to the impl. */
  register(name: string, handler: Handler): void {
    this.handlers.set(name, { handler, wasm: null });
    this.records.forget(name);
  }

  /** Wire the admission policy the loader gates bundle modules with (README §12.5).
   *  Null (the default) refuses every bind, so a host that never calls this loads no
   *  app at all — deny-all (README §14). */
  setAdmitPolicy(admit: AdmitPolicy | null): void {
    this.records.setPolicy(admit);
  }

  /** Read-only access to the install record at `name`, or null. Host-side read of the
   *  loader's records (README §12.4) — there is no wire query. */
  lookupInstall(name: string): InstallRecord | null {
    return this.records.lookup(name);
  }

  /** Admit a bundle module under its manifest-declared kernel name (README §12.4). The
   *  signed manifest already authenticated the coherent set and pinned each module's
   *  content hash, so the loader admits verified bytes here — bundles are the only way
   *  code arrives. The record's author is the manifest `authorPubKey` (a 32-byte Ed25519
   *  key, §12.4), gated by the admission policy. Returns true on success, false if no
   *  policy is wired or it refuses. The bundle loader calls this once per verified module. */
  installBundleModule(name: string, wasm: Uint8Array, authorPubKey: Uint8Array): boolean {
    return this.records.admit(name, wasm, authorPubKey);
  }

  /** Remove a handler, the `SetHandler(name, null)` case in §3.1 — and the loader's
   *  `remove(name)` revocation path (§12.5): it clears the slot's install record too, so
   *  the same key cannot later be misattributed onto brand-new bytes. */
  removeHandler(name: string): boolean {
    if (!this.handlers.delete(name)) return false;
    this.records.forget(name);
    return true;
  }

  /** True if a handler occupies `name`. The loader's admission consults it (via
   *  `InstallRecords`) to refuse overlaying a hand-seeded slot. */
  isRegistered(name: string): boolean {
    return this.handlers.has(name);
  }

  /** A bootstrap handler name (README §5.1): the literal-ASCII
   *  `"seedkernel.bootstrap.v1:" + canonical`. Bootstrap names are plain ASCII,
   *  not genesis-hash-derived — so names read plainly in logs.
   *
   *  For HAND-SEEDED slots only (`register`, §9). Bundle modules never come through
   *  here: the loader derives their names from the signed manifest (`kernelNameFor`),
   *  and the two namespaces are disjoint so an admitted bundle cannot land on a
   *  bootstrap slot. */
  deriveBootstrapName(canonical: string): string {
    return "seedkernel.bootstrap.v1:" + canonical;
  }

  /** Hash the raw bytes of `data` with the genesis hash (BLAKE2b-256) — the one system
   *  hash (the guest `HASH` op, the AKE KDF/transcript, and the block-id path all use it
   *  too, §12.1). Used by the loader's admission to compute a module's install-record
   *  `bytesHash` (§12.4), and exposed so deployers can compute the same hash off-line for
   *  policy allowlists. */
  genesisHash(data: Uint8Array): Uint8Array {
    return this.sodium.crypto_generichash(32, data, null);
  }

  /** Derive a deterministic name as `hex(BLAKE2b-256(canonical || authorPubKey))`.
   *
   *  A convenience for HAND-SEEDED slots (`register`, §9) in a deployment that wires the
   *  same canonical handler for several parties and wants each to hold its own — two
   *  `chat` slots that do not collide. Like `deriveBootstrapName`, it plays no part in
   *  bundle admission: a bundle module's name is derived from its signed manifest, so a
   *  policy has no name to constrain. The table is indifferent to derivation. */
  deriveScopedName(canonical: string, authorPubKey: Uint8Array): string {
    const nameBytes = new TextEncoder().encode(canonical);
    const buf = new Uint8Array(nameBytes.length + authorPubKey.length);
    buf.set(nameBytes, 0);
    buf.set(authorPubKey, nameBytes.length);
    return toHex(this.sodium.crypto_generichash(32, buf, null));
  }
}
