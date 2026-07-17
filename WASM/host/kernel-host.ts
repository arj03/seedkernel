// Host driver that loads kernel.wasm + the signature module (a stateless,
// standard scratch-ABI handler, §4) and wires them together.
//
// The host is the orchestrator:
//   - Owns the signer stack (§6.5) and drives the push/dispatch/pop lifecycle
//     around each verified `signature` wrapper:
//       1. kernel invokes the signature handler
//       2. host runs it through the standard §4 scratch ABI; a verified wrapper
//          returns [algo_id][signer_len][signer][inner]
//       3. host pushes the signer, dispatches the inner envelope, pops on return
//     so "pushed ⟺ verified" is a three-line host-local invariant.
//   - Provides libsodium Ed25519 + SHA-3-256 as the genesis suite handler (§6.2)
//   - Routes invoke_handler callbacks from kernel.wasm to WASM or host-JS handlers
//   - Provides kernel.call / kernel.caller imports to every handler (§4.2) — the
//     signature module reaches a suite by the same kernel.call to the suite's slot
//     name (§6.4, §6.6); no bespoke suite-dispatch import
//   - Exposes primitives the Installer (host/installer.ts) consumes:
//     instantiating WASM handlers + setHandler, genesis hashing, top-signer access

import { MAGIC, CURRENT_VERSION, MAX_ENVELOPE_BYTES } from "./envelope.js";
import { Installer, type ApproveInstall, type InstallRecord } from "./installer.js";
import { nameKey, toHex, writeU32BE } from "./util.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

export const GENESIS_ALGO_ID        = 0x0000;
export const GENESIS_PUBKEY_LEN     = 32;
export const GENESIS_SIGNATURE_LEN  = 64;
export const GENESIS_SECRET_KEY_LEN = 64;

// README §6.4: an algorithm suite is an ordinary scratch-ABI handler installed
// at a conventional slot name, the LITERAL-ASCII `SUITE_SLOT_PREFIX + algo_id_hex`.
// Slot names are plain ASCII, not genesis-hash-derived (§5.1), so the signature
// module builds the same name itself and reaches the suite by plain kernel.call.
// The genesis suite (Ed25519 + SHA-3-256, algo_id 0x0000) is seeded at that slot
// by the host at bootstrap and serviced with the bundled libsodium (§6.2, §13).
const SUITE_SLOT_PREFIX = "seedkernel.suite.v1:";

// README §6.3 / §16.1: the envelope-signature domain prefix. The signed preimage is
// `DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖ inner_envelope` (signer is length-
// prefixed so the preimage is self-delimiting); the prefix is prepended before
// signing/verifying but never transmitted, so a signature harvested in one context
// cannot verify in another.
const DOMAIN_ENV = new TextEncoder().encode("seedkernel-envelope-sig-v1\0");


/** Lowercase 4-hex-digit encoding of a u16 algo_id for suite slot names (§6.4). */
function algoIdHex(algoId: number): string {
  return (algoId & 0xffff).toString(16).padStart(4, "0");
}

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
  is_registered(namePtr: number, nameLen: number): number;
  find_handler(namePtr: number, nameLen: number): number;
  dispatch(bytesPtr: number, bytesLen: number): void;
}

// ─── handler routing ─────────────────────────────────────────────────────

const MAX_CALL_DEPTH = 8;

// README §2.3: cap nested `signature` wrappers per inbound message. Bounds the
// per-message verify cost so a single 64 KB envelope cannot force hundreds of
// crypto verifications on the single-threaded dispatch loop. Enforced here,
// host-side, because the signer stack lives here (§6.5).
const MAX_SIGNATURE_DEPTH = 4;

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

// Everything the host tracks about one installed handler, keyed by the kernel's
// handler id. The kernel owns the name → id table (its `find_handler` export is
// the one routing decision, consulted by both dispatch and kernel.call); the
// host owns only the per-id metadata the kernel doesn't need — the impl, the
// name (for kernel.caller), and whether kernel.call may reach it (§4.4). Exactly
// one of `handler` / `wasm` is set: a host-JS handler or a dynamic WASM handler.
interface HandlerEntry {
  name: Uint8Array;
  blocked: boolean;
  handler: Handler | null;
  wasm: WasmHandlerRef | null;
}

// nameKey now lives in util.ts, so the installer can key its records without
// importing this module (README §12.9 — the installer is bundled for the native
// loader, which has no KernelHost). Re-exported here for existing importers.
export { nameKey } from "./util.js";

export class KernelHost {
  private kernelExports!: KernelExports;
  private sodium!: Sodium;
  // Host-side handler state, keyed by the kernel's handler id. The kernel owns
  // the name → id table (find_handler); the host owns only per-id metadata, so
  // there is no name mirror to drift from what dispatch sees.
  private entries = new Map<number, HandlerEntry>();
  private nextHandlerId = 1;
  private callDepth = 0;
  // Call-chain tracking for kernel.caller (§4.2). Outermost is first, immediate
  // caller is last (push order).
  private callerStack: (Uint8Array | null)[] = [];
  // The signer stack (README §6.5): the keys verified during the current
  // top-level dispatch, outermost first. Owned here, not in the signature module —
  // _handleSignature pushes a verified signer, dispatches the inner envelope under
  // it, and pops on return, so the stack is always balanced.
  private signerStack: Signer[] = [];
  // Handler id of the `signature` wrapper, set by registerSignature; -1 until
  // then, so no invoke_handler id ever matches it before registration.
  private signatureId = -1;
  // The signature module's WASM bytes, kept from load() so registerSignature can
  // instantiate it as an ordinary handler once the host knows its name.
  private _signatureBytes!: Uint8Array;
  // Name used to build outer signature envelopes in wrap(). Set by
  // registerSignature; null until then.
  private _signatureName: Uint8Array | null = null;
  // The installer instance, if registerInstaller was called.
  private _installer: Installer | null = null;
  // Public keys that have already passed crypto_core_ed25519_is_valid_point
  // (§6.3). That check is a full elliptic-curve operation — as costly as the
  // signature verify itself — and a key's validity is a fixed property of its
  // bytes, so we run it once per distinct signer and cache the result instead
  // of repeating it on every message. Only *valid* keys are cached; invalid
  // ones are re-checked (and rejected) each time, so an attacker cannot grow
  // this set with garbage. Bounded to cap memory: a flood of distinct valid
  // keys evicts oldest-first (FIFO via Set insertion order).
  private validatedPubkeys = new Set<string>();
  private static readonly MAX_VALIDATED_PUBKEYS = 4096;

  private constructor() {}

  /** Instantiate the kernel from in-memory bytes and keep the signature module's
   *  bytes for `registerSignature` to instantiate as an ordinary handler (§4). The
   *  caller supplies the bytes and an initialized libsodium for Ed25519 +
   *  SHA-3-256 — keeping the entry point free of Node- or browser-specific I/O is
   *  what lets the same host run in Node, browsers, Deno, Bun, etc. The thin entry
   *  points in `node.ts` / `browser.ts` package the loading dance for each
   *  platform. */
  static async load(
    kernelBytes: BufferSource,
    signatureBytes: BufferSource,
    sodium: Sodium,
  ): Promise<KernelHost> {
    const host = new KernelHost();
    host.sodium = sodium;
    host._signatureBytes = ArrayBuffer.isView(signatureBytes)
      ? new Uint8Array(signatureBytes.buffer, signatureBytes.byteOffset, signatureBytes.byteLength)
      : new Uint8Array(signatureBytes);

    // ── load kernel.wasm ──────────────────────────────────────────────
    const kernelImports: WebAssembly.Imports = {
      env: {
        invoke_handler: (
          handlerId: number,
          namePtr: number,
          nameLen: number,
          payloadPtr: number,
          payloadLen: number
        ) => {
          host._onInvokeHandler(handlerId, namePtr, nameLen, payloadPtr, payloadLen);
        },
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
   *  (kernel.call routing, callHandler, the test helpers) so they can never
   *  disagree with what `dispatch` sees. */
  private findHandlerId(name: Uint8Array): number {
    const ptr = this.writeToKernel(name);
    try { return this.kernelExports.find_handler(ptr, name.length); }
    finally { this.kernelExports.dealloc(ptr); }
  }

  /** Bind `name` to `id` in the kernel table and record `entry` host-side,
   *  dropping whatever entry the name was previously bound to. Centralizes the
   *  "one name ⇒ one handler id" bookkeeping so register / _installWasmHandler
   *  can't leave a stale entry behind. The old id is resolved (find_handler)
   *  before the rebind (set_handler) inside a single kernel-memory staging so
   *  displacement sees the pre-rebind table. */
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

  // ─── import implementations ──────────────────────────────────────────

  /** Called by kernel.wasm when a handler matches (§3). */
  private _onInvokeHandler(
    handlerId: number,
    namePtr: number,
    nameLen: number,
    payloadPtr: number,
    payloadLen: number
  ): void {
    const payload = this.readFromKernel(payloadPtr, payloadLen);
    if (handlerId === this.signatureId) {
      this._handleSignature(payload);
      return;
    }

    // Dynamic WASM handler or host-JS handler — response is dropped for
    // inbound dispatch. kernel.call is the path that surfaces responses.
    const name = this.readFromKernel(namePtr, nameLen);
    this._invokeHandlerGetResponse(handlerId, name, payload);
  }

  /** Drive one accepted `signature` wrapper (README §6.5). The wrapper is a
   *  stateless standard-ABI handler (§4): it parses + verifies and returns
   *  `[algo_id u16][signer_len u16][signer][inner]` on success, or nothing to
   *  drop. The host owns the signer stack and the push/dispatch/pop lifecycle, so
   *  the "pushed ⟺ verified" invariant is the three lines below and no failure in
   *  the module can leak a signer onto the stack. */
  private _handleSignature(payload: Uint8Array): void {
    // README §2.3: reject before any verify work once the stack is full.
    if (this.signerStack.length >= MAX_SIGNATURE_DEPTH) return;

    const out = this._invokeHandlerGetResponse(this.signatureId, this._signatureName!, payload);
    // No output ⇒ malformed wrapper or the suite reported invalid ⇒ drop (§6.3).
    if (!out) return;

    // Parse [algo_id u16][signer_len u16][signer][inner].
    let o = 0;
    if (o + 4 > out.length) return;
    const algoId = (out[o] << 8) | out[o + 1]; o += 2;
    const signerLen = (out[o] << 8) | out[o + 1]; o += 2;
    if (signerLen <= 0 || o + signerLen > out.length) return;
    const publicKey = out.slice(o, o + signerLen); o += signerLen;
    const inner = out.slice(o);
    if (inner.length === 0) return;

    // Push the verified signer, dispatch the inner envelope under it, pop. Any
    // throw in dispatch unwinds through the finally, so the stack stays balanced.
    this.signerStack.push({ algoId, publicKey });
    try {
      const kPtr = this.writeToKernel(inner);
      try { this.kernelExports.dispatch(kPtr, inner.length); }
      catch { /* drop */ }
      finally { this.kernelExports.dealloc(kPtr); }
    } finally {
      this.signerStack.pop();
    }
  }

  /** Core invocation used both by inbound dispatch (response dropped) and by
   *  kernel.call (response returned to caller). Returns the handler's response
   *  bytes, or null if no response / no handler. */
  private _invokeHandlerGetResponse(
    handlerId: number,
    name: Uint8Array,
    payload: Uint8Array
  ): Uint8Array | null {
    const entry = this.entries.get(handlerId);
    if (!entry) return null;
    const wasm = entry.wasm;
    if (wasm) {
      // Scratch-region contract (README §4): write input at the handler's
      // scratch offset, call handle(input_len), read response from the
      // same offset.
      if (payload.length > wasm.scratchSize) return null;
      new Uint8Array(wasm.memory.buffer, wasm.scratch, payload.length).set(payload);
      let responseLen: number;
      try { responseLen = wasm.handle(payload.length); }
      catch { return null; }
      // handle returns output_len ≥ 0 (§4): only a trap or a negative/oversized
      // length is a failure. Zero is a valid EMPTY response — return an empty
      // array for it, distinct from null, so kernel.call can tell "empty OK"
      // (0, §4.4) from "no handler / trap" (-1).
      if (responseLen < 0 || responseLen > wasm.scratchSize) return null;
      return new Uint8Array(wasm.memory.buffer, wasm.scratch, responseLen).slice();
    }
    const handler = entry.handler;
    if (handler) {
      // An exception aborts the call but must not unwind through dispatch
      // and corrupt the signer stack or kernel state above it.
      try {
        const r = handler(name, payload, this);
        return r instanceof Uint8Array ? r : null;
      } catch {
        return null;
      }
    }
    return null;
  }

  /** Serialize the current signer stack as
   *  `[count u8][algo_id u16 BE][pubkey_len u16 BE][pubkey ..]*` — the format
   *  the `signature.signer` query handler returns (§6.5). pubkey_len is u16
   *  BE so post-quantum suites with multi-kilobyte public keys fit. */
  private _serializeSignerStack(): Uint8Array {
    const count = this.signerStack.length;
    if (count === 0) return new Uint8Array([0]);
    let size = 1;
    for (const s of this.signerStack) size += 2 + 2 + s.publicKey.length;
    const out = new Uint8Array(size);
    let o = 0;
    out[o++] = count; // capped at MAX_SIGNATURE_DEPTH, fits a u8
    for (const s of this.signerStack) {
      out[o++] = (s.algoId >> 8) & 0xff;
      out[o++] = s.algoId & 0xff;
      out[o++] = (s.publicKey.length >> 8) & 0xff;
      out[o++] = s.publicKey.length & 0xff;
      out.set(s.publicKey, o);
      o += s.publicKey.length;
    }
    return out;
  }

  /** Serialize the **immediate** caller into the `[name_len u8][name ..]`
   *  format the kernel.caller import returns (§4.2). No caller (top-level
   *  dispatch, or a host/guest-originated frame) returns the single byte
   *  [0x00] (name_len = 0). Only the immediate caller is ever exposed — the
   *  deeper chain is deliberately unreachable so a handler cannot treat a
   *  non-immediate frame as authoritative (§4.2, §8). */
  private _serializeImmediateCaller(): Uint8Array {
    const n = this.callerStack.length ? this.callerStack[this.callerStack.length - 1] : null;
    if (!n) return new Uint8Array([0]);
    const out = new Uint8Array(1 + n.length);
    out[0] = n.length;
    out.set(n, 1);
    return out;
  }

  /** Instantiate a dynamic WASM handler and install it via SetHandler. Called
   *  by the Installer (README §7.2 step 7) — the installer is responsible for
   *  authoring records; this method just turns "here are the bytes" into "the
   *  module is now wired to the kernel". Returns true on success, false on any
   *  failure (instantiation error, missing exports, scratch out of range). */
  _installWasmHandler(targetName: Uint8Array, wasmBytes: Uint8Array): boolean {
    if (targetName.length === 0) return false;
    if (wasmBytes.length === 0) return false;

    const handlerId = this.nextHandlerId++;
    let instance: WebAssembly.Instance;
    try {
      const mod = new WebAssembly.Module(wasmBytes as BufferSource);
      const imports: WebAssembly.Imports = {
        kernel: {
          call: (nPtr: number, nLen: number, plPtr: number, plLen: number): number =>
            this._kernelCallFromHandler(handlerId, nPtr, nLen, plPtr, plLen),
          caller: (outPtr: number): number => this._kernelCallerFromHandler(handlerId, outPtr),
        },
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
    // than the 128 KB default (README §4.1, "set per handler at instantiation") —
    // e.g. the storage codec reserves a whole chunk's worth of blocks. Honor it only
    // when it names real, in-bounds memory the handler actually reserved past
    // `scratch`; otherwise fall back to the default. Never shrink below the default.
    let scratchSize = DEFAULT_SCRATCH_SIZE;
    if (exps.scratchSize instanceof WebAssembly.Global) {
      const declared = exps.scratchSize.value as number;
      if (typeof declared === "number" && declared >= DEFAULT_SCRATCH_SIZE &&
          scratchOffset + declared <= exps.memory.buffer.byteLength) {
        scratchSize = declared;
      }
    }

    // SetHandler is unconditional at the kernel level — replace whatever is
    // there (bindHandler drops the displaced id's host entry). The installer's
    // replacement policy was applied before this method was called.
    this.bindHandler(targetName, handlerId, {
      name: targetName.slice(),
      blocked: false,
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

  /** Top-of-stack signer, or null if the signer stack is empty. */
  get currentTopSigner(): Signer | null {
    const n = this.signerStack.length;
    if (n === 0) return null;
    const s = this.signerStack[n - 1];
    return { algoId: s.algoId, publicKey: s.publicKey.slice() };
  }

  /** Host import provided to dynamic handlers as `kernel.call` (README §4.4). */
  private _kernelCallFromHandler(
    callerHandlerId: number,
    namePtr: number, nameLen: number,
    payloadPtr: number, payloadLen: number
  ): number {
    if (this.callDepth >= MAX_CALL_DEPTH) return -1;
    const callerEntry = this.entries.get(callerHandlerId);
    const caller = callerEntry?.wasm;
    if (!caller) return -1;
    // The four pointers come straight from the calling handler and may be out
    // of range (bad offset, negative length, run past the end of memory).
    // README §4.4 says kernel.call returns -1 on such errors; a thrown
    // RangeError here would instead unwind and abort the caller's entire
    // handle(), denying it the chance to observe the failed call and continue.
    let name: Uint8Array;
    let payload: Uint8Array;
    try {
      name = new Uint8Array(caller.memory.buffer, namePtr, nameLen).slice();
      payload = new Uint8Array(caller.memory.buffer, payloadPtr, payloadLen).slice();
    } catch {
      return -1;
    }
    // Route through the kernel's find_handler — the same table dispatch uses —
    // so the two paths can never resolve a name differently (README §4.4).
    const targetId = this.findHandlerId(name);
    if (targetId < 0) return -1;
    const target = this.entries.get(targetId);
    if (!target || target.blocked) return -1;

    // Push caller name onto the stack so kernel.caller works in the target.
    this.callerStack.push(callerEntry.name);

    this.callDepth++;
    let response: Uint8Array | null = null;
    try { response = this._invokeHandlerGetResponse(targetId, name, payload); }
    finally {
      this.callDepth--;
      this.callerStack.pop();
    }
    // null = trap or no output at all — an error (-1, §4.4). A genuine
    // zero-length response is a non-null empty array and returns 0 below,
    // leaving the caller's scratch untouched.
    if (!response) return -1;
    if (response.length > caller.scratchSize) return -1;
    new Uint8Array(caller.memory.buffer, caller.scratch, response.length).set(response);
    return response.length;
  }

  /** Host import provided to dynamic handlers as `kernel.caller` (§4.2).
   *  Writes the **immediate** caller at outPtr as `[name_len u8][name ..]` and
   *  returns the total bytes written. No caller writes the single byte [0x00]
   *  (name_len = 0) and returns 1. The deeper chain is never exposed. */
  private _kernelCallerFromHandler(callerHandlerId: number, outPtr: number): number {
    const caller = this.entries.get(callerHandlerId)?.wasm;
    if (!caller) return 0;
    const bytes = this._serializeImmediateCaller();
    if (outPtr + bytes.length > caller.memory.buffer.byteLength) return 0;
    new Uint8Array(caller.memory.buffer, outPtr, bytes.length).set(bytes);
    return bytes.length;
  }

  /** The genesis suite handler (algo_id 0x0000 = Ed25519 + SHA-3-256). Seeded
   *  by `registerSignature` at the genesis suite slot (§6.4) and reached like any
   *  ordinary handler by a plain `kernel.call` — the signature wrapper calls it
   *  the same way any handler calls any other. Standard scratch-ABI
   *  request/response (§6.6):
   *
   *    verify: [pk_len u16][pk][sig_len u16][sig][data ..] → [valid u8]
   *
   *  Verify is the suite's whole contract (§6.6) — no op selector, and the
   *  reference host derives ids directly, so there is no hash op.
   *
   *  `data` is the full signed preimage the signature module assembled
   *  (`DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖ inner_envelope`, §6.3); the suite
   *  is oblivious to its structure and just verifies `sig` over `data` under `pk`.
   *
   *  The raw public-key bytes are the signer's identity (and the canonical
   *  replay key, §4.4), so the key is validated before use: non-canonical /
   *  small-order encodings are rejected so one logical key has exactly one byte
   *  form (§6.3). libsodium's verify already rejects them internally; the extra
   *  `crypto_core_ed25519_is_valid_point` gate (when the build exposes it) makes
   *  the guarantee explicit and independent of the verify path. */
  private readonly _genesisSuiteHandler: Handler = (_name, req) => {
    const INVALID = new Uint8Array([0]);
    let o = 0;
    if (o + 2 > req.length) return INVALID;
    const pkLen = (req[o] << 8) | req[o + 1]; o += 2;
    if (pkLen !== GENESIS_PUBKEY_LEN || o + pkLen > req.length) return INVALID;
    const pk = req.slice(o, o + pkLen); o += pkLen;
    if (o + 2 > req.length) return INVALID;
    const sigLen = (req[o] << 8) | req[o + 1]; o += 2;
    if (sigLen !== GENESIS_SIGNATURE_LEN || o + sigLen > req.length) return INVALID;
    const sig = req.slice(o, o + sigLen); o += sigLen;
    const data = req.slice(o);
    try {
      if (!this._pubkeyIsValidPoint(pk)) return INVALID;
      return this.sodium.crypto_sign_verify_detached(sig, data, pk)
        ? new Uint8Array([1]) : INVALID;
    } catch { return INVALID; }
  };

  /** Gate on crypto_core_ed25519_is_valid_point (canonical encoding +
   *  prime-order subgroup), memoizing the result per distinct key. Builds that
   *  don't expose the symbol (the kernel-only libsodium build) return true and
   *  rely on the equivalent rejection crypto_sign_verify_detached performs
   *  internally — matching the pre-sumo behavior. */
  private _pubkeyIsValidPoint(pub: Uint8Array): boolean {
    const isValidPoint = (this.sodium as unknown as {
      crypto_core_ed25519_is_valid_point?: (p: Uint8Array) => boolean;
    }).crypto_core_ed25519_is_valid_point;
    if (typeof isValidPoint !== "function") return true;
    const key = nameKey(pub);
    if (this.validatedPubkeys.has(key)) return true;
    if (!isValidPoint(pub)) return false;
    if (this.validatedPubkeys.size >= KernelHost.MAX_VALIDATED_PUBKEYS) {
      const oldest = this.validatedPubkeys.values().next().value;
      if (oldest !== undefined) this.validatedPubkeys.delete(oldest);
    }
    this.validatedPubkeys.add(key);
    return true;
  }

  /** The conventional slot name a suite for `algoId` is installed at (README
   *  §6.4): the literal-ASCII `SUITE_SLOT_PREFIX + algo_id_hex`. A suite is an
   *  ordinary handler at this name — no registry, no separate ABI. The name is
   *  plain ASCII (not genesis-hash-derived, §5.1), so the signature module
   *  builds the byte-identical name and reaches the suite by plain kernel.call. */
  deriveSuiteSlotName(algoId: number): Uint8Array {
    return new TextEncoder().encode(SUITE_SLOT_PREFIX + algoIdHex(algoId));
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** The name of the **immediate** caller — the handler whose `kernel.call`
   *  reached the current one — or null when it was invoked directly from the
   *  pipeline (or by a host/guest-originated frame). Host-side equivalent of
   *  the kernel.caller WASM import (§4.2). Only the immediate caller is exposed;
   *  the deeper chain is deliberately unreachable so a bridge cannot authorize
   *  on a non-immediate frame (§8). */
  get currentCaller(): Uint8Array | null {
    if (this.callerStack.length === 0) return null;
    return this.callerStack[this.callerStack.length - 1] ?? null;
  }

  /** Read-only access to the install record at `name`, or null. Host-side
   *  read of the installer's records — the policy callback already receives the
   *  resolved `existing` record, so there is no wire query (README §7.6). */
  lookupInstall(name: Uint8Array): InstallRecord | null {
    return this._installer ? this._installer.lookup(name) : null;
  }

  /** Install a bundle module directly under its manifest-declared kernel name
   *  (README §12.4). The signed manifest already authenticated the coherent set
   *  and pinned each module's content hash, so the loader installs verified bytes
   *  here rather than dispatching a redundant per-module `.install` envelope —
   *  lifting the §2.2 64 KB envelope cap for bundled modules and removing the
   *  boot-time `seq` re-dispatch. The install record's author is the manifest
   *  `authorPubKey` (an Ed25519 genesis key, §12.4); the same install policy still
   *  gates it (§12.4 "two gates"). Returns true on success, false if no installer
   *  is wired or the policy refuses. */
  installBundleModule(name: Uint8Array, wasm: Uint8Array, authorPubKey: Uint8Array): boolean {
    if (!this._installer) return false;
    return this._installer.installDirect(name, wasm, { algoId: GENESIS_ALGO_ID, publicKey: authorPubKey });
  }

  /** Read the current signer stack (§6.5), outermost first. */
  get currentSigners(): readonly Signer[] {
    return this.signerStack.map((s) => ({ algoId: s.algoId, publicKey: s.publicKey.slice() }));
  }

  /** Host-level handler management (README §3.1). Installs or replaces a
   *  handler unconditionally. SetHandler-installed handlers are immune to
   *  installer state by construction (§8) — any matching install record
   *  is cleared as a side effect. */
  setHandler(name: Uint8Array, handlerId: number): void {
    // Bind an already-registered id under `name`, displacing whatever was there.
    // Unlike register / _installWasmHandler this does not create the impl — the
    // entry for `handlerId` is expected to exist already, so merge the name into
    // it rather than clobbering its handler/wasm ref.
    const ptr = this.writeToKernel(name);
    let oldId: number;
    try {
      oldId = this.kernelExports.find_handler(ptr, name.length);
      this.kernelExports.set_handler(ptr, name.length, handlerId);
    } finally { this.kernelExports.dealloc(ptr); }
    if (oldId >= 0 && oldId !== handlerId) this.entries.delete(oldId);
    const entry = this.entries.get(handlerId);
    if (entry) entry.name = name.slice();
    else this.entries.set(handlerId, { name: name.slice(), blocked: false, handler: null, wasm: null });
    // SetHandler entries are bootstrap-only by construction (§3.1) — clear
    // any stale install record at this slot so a future lookup can't return
    // stale data for brand-new bytes (§3.1 "Replacing installer-managed names").
    if (this._installer) this._installer._onKernelSlotMutated(name);
  }

  /** Remove a handler installed via setHandler (null handler case in §3.1). */
  removeHandler(name: Uint8Array): boolean {
    const ptr = this.writeToKernel(name);
    try {
      const id = this.kernelExports.find_handler(ptr, name.length);
      const ok = this.kernelExports.remove_handler(ptr, name.length) === 1;
      if (ok) {
        if (id >= 0) this.entries.delete(id);
        if (this._installer) this._installer._onKernelSlotMutated(name);
      }
      return ok;
    } finally { this.kernelExports.dealloc(ptr); }
  }

  /** Register the signature wrapper handler (§6.5) and seed the genesis suite
   *  (§6.2) at its slot. Required for any signed message to dispatch: the
   *  wrapper verifies via the suite installed at the algo's slot (§6.4), and the
   *  genesis suite (Ed25519 + SHA-3-256) is the one that must exist at boot.
   *
   *  The wrapper is an ordinary scratch-ABI WASM handler (§4) — the host
   *  instantiates it and SetHandler-seeds it here, like any bootstrap handler
   *  (§9). It is privileged only in that the host recognizes its id and drives
   *  the signer-stack lifecycle around its output (_handleSignature), never in its
   *  ABI. Being SetHandler-seeded with no install record, the reference policy
   *  refuses to overlay it (§6.4) and the host keeps the emergency-replacement
   *  path (§9.1). Blocked from `kernel.call` (§4.4): the wrapper establishes the
   *  top signer, so letting a handler invoke it would let it reframe the active
   *  signer mid-chain. */
  registerSignature(signatureName: Uint8Array): void {
    if (!this._installWasmHandler(signatureName, this._signatureBytes)) {
      throw new Error("registerSignature: failed to instantiate the signature module");
    }
    const id = this.findHandlerId(signatureName);
    if (id < 0) throw new Error("registerSignature: signature handler id missing");
    this.signatureId = id;
    this._signatureName = signatureName.slice();
    this.blockFromCall(id);
    this.register(this.deriveSuiteSlotName(GENESIS_ALGO_ID), this._genesisSuiteHandler);
  }

  /** Register the `signature.signer` query handler (§6.5): an ordinary host
   *  handler that serializes the host-owned signer stack. Any handler that wants
   *  to read the current signer stack via `kernel.call(signerQueryName, …)` needs
   *  this wired. Optional — the wrapper works without it; only apps that
   *  introspect the author of a dispatch require it. */
  registerSignerQuery(signerQueryName: Uint8Array): void {
    this.register(signerQueryName, () => this._serializeSignerStack());
  }

  /** Mark a handler as forbidden from `kernel.call` (README §4.4). Use this
   *  for any deployer-added handler that calls `kernel.SetHandler` internally
   *  or that re-dispatches under a new author. The signature wrapper is blocked
   *  by registerSignature; the installer is blocked when registerInstaller runs.
   *  Idempotent. */
  blockFromCall(handlerId: number): void {
    const entry = this.entries.get(handlerId);
    if (entry) entry.blocked = true;
  }

  /** Register the Installer (README §7). Wires the (blocked) install message
   *  handler — the installer's whole wire surface. Install records are read
   *  host-side via `lookupInstall`; there is no `installer.lookup` /
   *  `installer.caps_of` query message (README §7.6). Without calling this, the
   *  deployment is frozen — no message-driven installs. Returns the Installer
   *  instance for further configuration. */
  registerInstaller(installName: Uint8Array): Installer {
    const ih = new Installer(this);
    const id = this.register(installName, ih.handler);
    this.blockFromCall(id);
    this._installer = ih;
    return ih;
  }

  /** Convenience: wire the install-approval callback on the installer. Throws
   *  if registerInstaller has not been called. */
  setApproveInstall(callback: ApproveInstall | null): void {
    if (!this._installer) {
      throw new Error("setApproveInstall: registerInstaller must be called first");
    }
    this._installer.setApproveInstall(callback);
  }

  /** Build an install payload (README §7.2):
   *    [seq u32 BE]
   *    [name_len u8][name ..]
   *    [wasm]
   *
   *  `seq` is the §4.4 replay-protection sequence number for the signer. */
  encodeInstallPayload(
    seq: number,
    name: Uint8Array,
    wasmBytes: Uint8Array,
  ): Uint8Array {
    if (name.length === 0 || name.length > 255)
      throw new Error("encodeInstallPayload: name length must be 1..255");
    if (!Number.isSafeInteger(seq) || seq < 0 || seq > 0xffffffff)
      throw new Error("encodeInstallPayload: seq must fit in u32");
    const headerLen = 4 + 1 + name.length; // seq + name_len + name
    const out = new Uint8Array(headerLen + wasmBytes.length);
    let o = 0;
    writeU32BE(out, o, seq); o += 4;
    out[o++] = name.length;
    out.set(name, o); o += name.length;
    out.set(wasmBytes, o);
    return out;
  }

  /** Test helper: call an arbitrary `(): i32` export on a dynamic WASM handler. */
  callDynamicHandlerI32(name: Uint8Array, exportName: string): number | null {
    const hid = this.findHandlerId(name);
    if (hid < 0) return null;
    const wasm = this.entries.get(hid)?.wasm;
    if (!wasm) return null;
    const fn = (wasm.exports as { [k: string]: unknown })[exportName];
    if (typeof fn !== "function") return null;
    return (fn as () => number)();
  }

  /** Call a named export on a dynamic WASM handler, staging `payload` in
   *  scratch first. Returns the export's i32 return value or null on failure. */
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

  /** Invoke an installed handler by name with `payload`, returning its response
   *  bytes (the standard `handle` scratch ABI), or null if the name is unbound
   *  or the handler produced no response. The generic "call a module" primitive
   *  an app cap-bridge uses to reach installed WASM (e.g. a codec or reputation
   *  handler) without the kernel knowing what they are — the host counterpart of
   *  a WASM handler's `kernel.call(name, payload)`. */
  callHandler(name: Uint8Array, payload: Uint8Array): Uint8Array | null {
    const hid = this.findHandlerId(name);
    if (hid < 0) return null;
    // Same guards as the kernel.call router (§4.4): a handler the router would
    // refuse (signature wrapper, installer, deployer-blocked mutators) must not
    // become reachable by name through this host-side path either.
    const entry = this.entries.get(hid);
    if (!entry || entry.blocked) return null;
    if (this.callDepth >= MAX_CALL_DEPTH) return null;
    // Push an anonymous caller frame so the target (and any bridge doing the
    // §8 caller-pinning check) sees "no installed caller" rather than a stale
    // frame from an outer dispatch — the host/guest caller has no kernel name.
    this.callerStack.push(null);
    this.callDepth++;
    try { return this._invokeHandlerGetResponse(hid, name, payload); }
    finally {
      this.callDepth--;
      this.callerStack.pop();
    }
  }

  /** Register a host-side handler. Returns the assigned id. */
  register(name: Uint8Array, handler: Handler): number {
    const id = this.nextHandlerId++;
    this.bindHandler(name, id, {
      name: name.slice(),
      blocked: false,
      handler,
      wasm: null,
    });
    if (this._installer) this._installer._onKernelSlotMutated(name);
    return id;
  }

  isRegistered(name: Uint8Array): boolean {
    const ptr = this.writeToKernel(name);
    try { return this.kernelExports.is_registered(ptr, name.length) === 1; }
    finally { this.kernelExports.dealloc(ptr); }
  }

  /** Feed raw envelope bytes into the pipeline. */
  dispatch(bytes: Uint8Array): void {
    if (bytes.length > MAX_ENVELOPE_BYTES) return;
    const ptr = this.writeToKernel(bytes);
    try {
      try { this.kernelExports.dispatch(ptr, bytes.length); }
      catch { /* drop */ }
    } finally { this.kernelExports.dealloc(ptr); }
  }

  /** Direct host-side access to the installer (read-only). Most code should
   *  go through the `lookupInstall` convenience wrapper. */
  get installer(): Installer | null {
    return this._installer;
  }

  /** A bootstrap handler name (README §5.1): the literal-ASCII
   *  `"seedkernel.bootstrap.v1:" + canonical`. Bootstrap names are plain ASCII,
   *  not genesis-hash-derived — so swapping the genesis suite no longer re-derives
   *  the bootstrap namespace (only `bytes_hash` still depends on the genesis hash),
   *  and names read plainly in logs. */
  deriveBootstrapName(canonical: string): Uint8Array {
    return new TextEncoder().encode("seedkernel.bootstrap.v1:" + canonical);
  }

  /** Hash the raw bytes of `data` with the genesis suite (SHA-3-256). Used
   *  by the installer to compute install record hashes and exposed so
   *  deployers can compute the same hash off-line for allowlists. */
  genesisHash(data: Uint8Array): Uint8Array {
    return this.sodium.crypto_hash_sha3256(data);
  }

  /** Derive a deterministic name as `SHA-3-256(canonical || installer_pubkey)`.
   *  Useful for deployer policies that want author-scoped names so two parties
   *  can each hold their own `chat` without conflict (§5.1). The kernel is
   *  indifferent to derivation — this is just a convenience. */
  deriveScopedName(canonical: string, authorPubKey: Uint8Array): Uint8Array {
    const nameBytes = new TextEncoder().encode(canonical);
    const buf = new Uint8Array(nameBytes.length + authorPubKey.length);
    buf.set(nameBytes, 0);
    buf.set(authorPubKey, nameBytes.length);
    return this.sodium.crypto_hash_sha3256(buf);
  }

  /** Encode an envelope (README §2). Pure binary layout — no security boundary
   *  on the encoder side, so it lives in the host. The kernel still enforces
   *  the §2.2 64 KB limit on decode, and rejects any version byte other than
   *  CURRENT_VERSION, so the encoder always writes CURRENT_VERSION. */
  encodeEnvelope(name: Uint8Array, payload: Uint8Array): Uint8Array {
    if (name.length === 0 || name.length > 255) throw new Error("encodeEnvelope: name length must be 1..255");
    const total = 4 + name.length + payload.length;
    if (total > MAX_ENVELOPE_BYTES) throw new Error("encodeEnvelope: envelope exceeds 64 KB");
    const out = new Uint8Array(total);
    out[0] = (MAGIC >> 8) & 0xff;
    out[1] = MAGIC & 0xff;
    out[2] = CURRENT_VERSION;
    out[3] = name.length;
    out.set(name, 4);
    out.set(payload, 4 + name.length);
    return out;
  }

  /** Sign + wrap an inner envelope in a signature envelope (README §6.3).
   *  Sender-side, genesis suite (Ed25519+SHA-3-256). Throws if the resulting
   *  envelope would exceed 65,536 bytes or if registerSignature has not been
   *  called. */
  wrap(privateKey: Uint8Array, publicKey: Uint8Array, innerBytes: Uint8Array): Uint8Array {
    if (!this._signatureName) throw new Error("wrap: registerSignature has not been called");
    if (privateKey.length !== GENESIS_SECRET_KEY_LEN) {
      throw new Error(`wrap: privateKey must be ${GENESIS_SECRET_KEY_LEN} bytes (Ed25519), got ${privateKey.length}`);
    }
    if (publicKey.length !== GENESIS_PUBKEY_LEN) {
      throw new Error(`wrap: publicKey must be ${GENESIS_PUBKEY_LEN} bytes (Ed25519), got ${publicKey.length}`);
    }

    const wrapperPayloadLen = 2 + 2 + GENESIS_PUBKEY_LEN + 2 + GENESIS_SIGNATURE_LEN + innerBytes.length;
    const projectedTotal = 4 + this._signatureName.length + wrapperPayloadLen;
    if (projectedTotal > MAX_ENVELOPE_BYTES) {
      throw new Error("wrap: envelope exceeds 64 KB");
    }
    // README §6.3: sign over `DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖
    // inner_envelope`, not the bare inner bytes. Folding the outer fields into the
    // preimage closes the algo_id/signer flip attacks, and length-prefixing the signer
    // makes the preimage self-delimiting so no other (signer, inner) split can hash to
    // the same bytes; the domain prefix keeps an envelope signature from verifying in any
    // other context. The prefix and outer fields are reconstructed by the verifier, never
    // transmitted (the wrapper carries signer_len already).
    const preimage = new Uint8Array(DOMAIN_ENV.length + 2 + 2 + GENESIS_PUBKEY_LEN + innerBytes.length);
    let p = 0;
    preimage.set(DOMAIN_ENV, p); p += DOMAIN_ENV.length;
    preimage[p++] = (GENESIS_ALGO_ID >> 8) & 0xff;
    preimage[p++] = GENESIS_ALGO_ID & 0xff;
    preimage[p++] = (GENESIS_PUBKEY_LEN >> 8) & 0xff;
    preimage[p++] = GENESIS_PUBKEY_LEN & 0xff;
    preimage.set(publicKey, p); p += GENESIS_PUBKEY_LEN;
    preimage.set(innerBytes, p);
    const sig = this.sodium.crypto_sign_detached(preimage, privateKey);
    const wrapperPayload = new Uint8Array(wrapperPayloadLen);
    let o = 0;
    wrapperPayload[o++] = (GENESIS_ALGO_ID >> 8) & 0xff;
    wrapperPayload[o++] = GENESIS_ALGO_ID & 0xff;
    wrapperPayload[o++] = (GENESIS_PUBKEY_LEN >> 8) & 0xff;
    wrapperPayload[o++] = GENESIS_PUBKEY_LEN & 0xff;
    wrapperPayload.set(publicKey, o); o += GENESIS_PUBKEY_LEN;
    wrapperPayload[o++] = (GENESIS_SIGNATURE_LEN >> 8) & 0xff;
    wrapperPayload[o++] = GENESIS_SIGNATURE_LEN & 0xff;
    wrapperPayload.set(sig, o); o += GENESIS_SIGNATURE_LEN;
    wrapperPayload.set(innerBytes, o);

    return this.encodeEnvelope(this._signatureName, wrapperPayload);
  }

  /** Convenience: encode an inner envelope then wrap + sign it. */
  wrapAndEncode(
    privateKey: Uint8Array, publicKey: Uint8Array,
    name: Uint8Array, payload: Uint8Array
  ): Uint8Array {
    const innerBytes = this.encodeEnvelope(name, payload);
    return this.wrap(privateKey, publicKey, innerBytes);
  }
}
