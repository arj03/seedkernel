// Host driver that loads kernel.wasm + bootstrap.wasm (signature module) and
// wires them together.
//
// The host is the orchestrator:
//   - Provides libsodium Ed25519 + SHA-3-256 to bootstrap.wasm
//   - Routes invoke_handler callbacks from kernel.wasm to bootstrap.wasm's
//     signature handler or to host-side JS handlers
//   - Drives the signature push/pop lifecycle (§6.5):
//       1. kernel invokes HANDLER_SIGNATURE
//       2. host calls bootstrap.handle_signature() → returns 1 if verified
//       3. host reads inner bytes from bootstrap memory, dispatches through kernel
//       4. host calls bootstrap.pop_signer() after inner dispatch returns
//   - Services the signature module's suite_verify import (§6.6) by dispatching
//     the verify request to the ordinary handler at the algo's suite slot
//     (§6.4) — genesis included, seeded as a host-serviced suite handler
//   - Provides kernel.call / kernel.caller imports to dynamic handlers (§4.2)
//   - Exposes primitives the Installer (host/installer.ts) consumes:
//     instantiating WASM handlers + setHandler, genesis hashing, top-signer access

import { MAGIC, CURRENT_VERSION, MAX_ENVELOPE_BYTES } from "./envelope.js";
import { Installer, type ApproveInstall, type InstallRecord } from "./installer.js";
import { toHex, writeU32BE } from "./util.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

export const GENESIS_ALGO_ID        = 0x0000;
export const GENESIS_PUBKEY_LEN     = 32;
export const GENESIS_SIGNATURE_LEN  = 64;
export const GENESIS_SECRET_KEY_LEN = 64;

// README §6.4: an algorithm suite is an ordinary scratch-ABI handler installed
// at a conventional slot name, `hash(SUITE_SLOT_PREFIX + algo_id_hex)`. The
// genesis suite (Ed25519 + SHA-3-256, algo_id 0x0000) is seeded at that slot by
// the host at bootstrap and serviced with the bundled libsodium (§6.2, §14).
const SUITE_SLOT_PREFIX = "seedkernel.signature.suite.v1:";

// README §6.3 / §17.1: the envelope-signature domain prefix. The signed preimage is
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
  handler_count(): number;
  dispatch(bytesPtr: number, bytesLen: number): void;
}

// ─── bootstrap.wasm exports (signature module only) ──────────────────────

interface BootstrapExports {
  memory: WebAssembly.Memory;
  alloc(size: number): number;
  dealloc(ptr: number): void;
  handle_signature(payloadPtr: number, payloadLen: number): number;
  get_inner_ptr(): number;
  get_inner_len(): number;
  pop_signer(): void;
  get_signer_count(): number;
  read_signer(index: number, outAlgoPtr: number, outPubPtr: number, outPubMaxLen: number): number;
  signer_pubkey_len(index: number): number;
}

// ─── handler routing ─────────────────────────────────────────────────────

const HANDLER_SIGNATURE        = -1;
const HANDLER_SIGNATURE_SIGNER = -2;

const MAX_CALL_DEPTH = 8;

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

export function nameKey(name: Uint8Array): string {
  return toHex(name);
}

// The u32-BE codec lives in util.ts; re-exported here because this module is
// where downstream consumers historically imported it from.
export { writeU32BE, readU32BE } from "./util.js";

export class KernelHost {
  private kernelExports!: KernelExports;
  private bootstrapExports!: BootstrapExports;
  private sodium!: Sodium;
  private handlers = new Map<number, Handler>();
  private wasmHandlers = new Map<number, WasmHandlerRef>();
  private nameToHandlerId = new Map<string, number>();
  private handlerIdToName = new Map<number, Uint8Array>();
  private nextHandlerId = 1;
  private callDepth = 0;
  // Call-chain tracking for kernel.caller (§4.2). Outermost is first, immediate
  // caller is last (push order).
  private callerStack: (Uint8Array | null)[] = [];
  // Handler IDs that kernel.call must refuse (README §4.4). The signature
  // wrapper is blocked by its sentinel; the installer's positive ID is added
  // when registerInstaller runs. Deployer-added mutators register via
  // blockFromCall.
  private blockedFromCall = new Set<number>([HANDLER_SIGNATURE]);
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

  /** Instantiate the kernel + bootstrap modules from in-memory bytes. The
   *  caller supplies the bytes and an initialized libsodium for Ed25519 +
   *  SHA-3-256 — keeping the entry point free of Node- or browser-specific
   *  I/O is what lets the same host run in Node, browsers, Deno, Bun, etc.
   *  The thin entry points in `node.ts` / `browser.ts` package the loading
   *  dance for each platform. */
  static async load(
    kernelBytes: BufferSource,
    bootstrapBytes: BufferSource,
    sodium: Sodium,
  ): Promise<KernelHost> {
    const host = new KernelHost();
    host.sodium = sodium;

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

    // ── load bootstrap.wasm (signature module) ────────────────────────
    const bootstrapImports: WebAssembly.Imports = {
      env: {
        // README §6.6: the signature module builds the suite verify request
        // (length-prefixed pubkey/sig/data, no op selector) in its own memory
        // and passes it here with the algo_id. The host derives the suite's slot
        // name (§6.4) and dispatches the request to whatever ordinary handler is
        // installed there — genesis included, which is seeded as a host-serviced
        // suite handler at bootstrap. Returns 1 iff the suite reports valid.
        suite_verify: (algoId: number, reqPtr: number, reqLen: number): number => {
          return host._suiteVerify(algoId, reqPtr, reqLen);
        },
        abort: (_msgPtr: number, _filePtr: number, line: number, col: number) => {
          throw new Error(`bootstrap.wasm abort at ${line}:${col}`);
        },
        seed: () => Date.now(),
        trace: () => {},
      },
    };
    const bootstrapResult = await WebAssembly.instantiate(bootstrapBytes, bootstrapImports);
    host.bootstrapExports = bootstrapResult.instance.exports as unknown as BootstrapExports;

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

  // ─── bootstrap memory helpers ────────────────────────────────────────

  private readFromBootstrap(ptr: number, len: number): Uint8Array {
    return new Uint8Array(this.bootstrapExports.memory.buffer, ptr, len).slice();
  }

  /** Allocate in bootstrap memory and copy len bytes from kernel memory at
   *  srcPtr → bootstrap[ret..ret+len]. Caller deallocates. */
  private _copyKernelToBootstrap(srcPtr: number, len: number): number {
    const dstPtr = this.bootstrapExports.alloc(len);
    new Uint8Array(this.bootstrapExports.memory.buffer, dstPtr, len)
      .set(new Uint8Array(this.kernelExports.memory.buffer, srcPtr, len));
    return dstPtr;
  }

  /** Mirror of _copyKernelToBootstrap going the other direction. */
  private _copyBootstrapToKernel(srcPtr: number, len: number): number {
    const dstPtr = this.kernelExports.alloc(len);
    new Uint8Array(this.kernelExports.memory.buffer, dstPtr, len)
      .set(new Uint8Array(this.bootstrapExports.memory.buffer, srcPtr, len));
    return dstPtr;
  }

  /** When a name is being rebound to a new handlerId, drop the old handler's
   *  host-side state. Kernel-side replacement is done separately by the
   *  kernel.wasm set_handler call. */
  private _displaceHandlerAtName(key: string, newId: number): void {
    const oldId = this.nameToHandlerId.get(key);
    if (oldId !== undefined && oldId !== newId) {
      this.wasmHandlers.delete(oldId);
      this.handlers.delete(oldId);
      this.handlerIdToName.delete(oldId);
      this.blockedFromCall.delete(oldId);
    }
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
    if (handlerId === HANDLER_SIGNATURE) {
      const payPtr = this._copyKernelToBootstrap(payloadPtr, payloadLen);
      // Snapshot the signer-stack depth so the drop path can undo a signer that
      // handle_signature pushed but then failed to commit (e.g. an allocation
      // threw after the push). The reference signature module pushes as its last
      // step, but the host must not depend on that: a leaked signer would
      // mis-attribute the next top-level message to a key that never signed it,
      // and accumulated leaks would fill MAX_SIGNATURE_DEPTH and wedge all
      // signed traffic.
      const signerCountBefore = this.bootstrapExports.get_signer_count();
      let verified = 0;
      try {
        try { verified = this.bootstrapExports.handle_signature(payPtr, payloadLen); }
        catch { verified = 0; }
      } finally {
        this.bootstrapExports.dealloc(payPtr);
      }
      if (!verified) {
        while (this.bootstrapExports.get_signer_count() > signerCountBefore) {
          this.bootstrapExports.pop_signer();
        }
        return;
      }

      // From here on the signer is on the bootstrap stack. Any throw before
      // pop_signer runs would leak the signer and let an unrelated later
      // message impersonate this one — wrap everything in a single finally.
      let kPtr = 0;
      try {
        const innerLen = this.bootstrapExports.get_inner_len();
        const innerPtr = this.bootstrapExports.get_inner_ptr();
        kPtr = this._copyBootstrapToKernel(innerPtr, innerLen);
        try { this.kernelExports.dispatch(kPtr, innerLen); }
        catch { /* drop — pop_signer in finally restores the stack */ }
      } finally {
        if (kPtr) this.kernelExports.dealloc(kPtr);
        this.bootstrapExports.pop_signer();
      }
      return;
    }

    // Dynamic WASM handler or host-JS handler — response is dropped for
    // inbound dispatch. kernel.call is the path that surfaces responses.
    const name = this.readFromKernel(namePtr, nameLen);
    const payload = this.readFromKernel(payloadPtr, payloadLen);
    this._invokeHandlerGetResponse(handlerId, name, payload);
  }

  /** Core invocation used both by inbound dispatch (response dropped) and by
   *  kernel.call (response returned to caller). Returns the handler's response
   *  bytes, or null if no response / no handler. */
  private _invokeHandlerGetResponse(
    handlerId: number,
    name: Uint8Array,
    payload: Uint8Array
  ): Uint8Array | null {
    if (handlerId === HANDLER_SIGNATURE_SIGNER) {
      return this._serializeSignerStack();
    }
    const wasm = this.wasmHandlers.get(handlerId);
    if (wasm) {
      // Scratch-region contract (README §4): write input at the handler's
      // scratch offset, call handle(input_len), read response from the
      // same offset.
      if (payload.length > wasm.scratchSize) return null;
      new Uint8Array(wasm.memory.buffer, wasm.scratch, payload.length).set(payload);
      let responseLen: number;
      try { responseLen = wasm.handle(payload.length); }
      catch { return null; }
      if (responseLen <= 0 || responseLen > wasm.scratchSize) return null;
      return new Uint8Array(wasm.memory.buffer, wasm.scratch, responseLen).slice();
    }
    const handler = this.handlers.get(handlerId);
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
    const count = this.bootstrapExports.get_signer_count();
    if (count === 0) return new Uint8Array([0]);
    const entries: { algo: number; pk: Uint8Array }[] = [];
    let size = 1;
    for (let i = 0; i < count; i++) {
      const s = this._readSignerAt(i);
      if (s === null) continue;
      entries.push({ algo: s.algoId, pk: s.pubKey });
      size += 2 + 2 + s.pubKey.length;
    }
    const out = new Uint8Array(size);
    let o = 0;
    out[o++] = entries.length;
    for (const e of entries) {
      out[o++] = (e.algo >> 8) & 0xff;
      out[o++] = e.algo & 0xff;
      out[o++] = (e.pk.length >> 8) & 0xff;
      out[o++] = e.pk.length & 0xff;
      out.set(e.pk, o);
      o += e.pk.length;
    }
    return out;
  }

  /** Serialize the **immediate** caller into the `[name_len u8][name ..]`
   *  format the kernel.caller import returns (§4.2). No caller (top-level
   *  dispatch, or a host/guest-originated frame) returns the single byte
   *  [0x00] (name_len = 0). Only the immediate caller is ever exposed — the
   *  deeper chain is deliberately unreachable so a handler cannot treat a
   *  non-immediate frame as authoritative (§4.2, §9). */
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
    // there. The installer's replacement policy was applied before this
    // method was called.
    const kPtr = this.writeToKernel(targetName);
    try {
      this.kernelExports.set_handler(kPtr, targetName.length, handlerId);
    } finally {
      this.kernelExports.dealloc(kPtr);
    }

    const targetKey = nameKey(targetName);
    this._displaceHandlerAtName(targetKey, handlerId);

    this.wasmHandlers.set(handlerId, {
      memory: exps.memory,
      scratch: scratchOffset,
      scratchSize,
      handle: exps.handle,
      exports: instance.exports,
    });

    this.nameToHandlerId.set(targetKey, handlerId);
    this.handlerIdToName.set(handlerId, targetName.slice());

    return true;
  }

  /** Top-of-stack signer, or null if the signer stack is empty. */
  get currentTopSigner(): Signer | null {
    const s = this._readTopSigner();
    if (!s) return null;
    return { algoId: s.algoId, publicKey: s.pubKey };
  }

  /** Read signer at index, sizing the pubkey buffer to the suite's actual
   *  pubkey length so post-quantum keys are not truncated. */
  private _readSignerAt(index: number): { algoId: number; pubKey: Uint8Array } | null {
    const required = this.bootstrapExports.signer_pubkey_len(index);
    if (required < 0) return null;
    if (required === 0) return null;
    const algoBuf = this.bootstrapExports.alloc(2);
    const pubBuf  = this.bootstrapExports.alloc(required);
    try {
      const pubLen = this.bootstrapExports.read_signer(index, algoBuf, pubBuf, required);
      if (pubLen < 0) return null;
      const mem = new DataView(this.bootstrapExports.memory.buffer);
      const algoId = (mem.getUint8(algoBuf) << 8) | mem.getUint8(algoBuf + 1);
      return { algoId, pubKey: this.readFromBootstrap(pubBuf, pubLen) };
    } finally {
      this.bootstrapExports.dealloc(algoBuf);
      this.bootstrapExports.dealloc(pubBuf);
    }
  }

  /** Read the top-of-stack signer from bootstrap.wasm. */
  private _readTopSigner(): { algoId: number; pubKey: Uint8Array } | null {
    const count = this.bootstrapExports.get_signer_count();
    if (count === 0) return null;
    return this._readSignerAt(count - 1);
  }

  /** Host import provided to dynamic handlers as `kernel.call` (README §4.4). */
  private _kernelCallFromHandler(
    callerHandlerId: number,
    namePtr: number, nameLen: number,
    payloadPtr: number, payloadLen: number
  ): number {
    if (this.callDepth >= MAX_CALL_DEPTH) return -1;
    const caller = this.wasmHandlers.get(callerHandlerId);
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
    const targetId = this.nameToHandlerId.get(nameKey(name));
    if (targetId === undefined) return -1;
    if (this.blockedFromCall.has(targetId)) return -1;

    // Push caller name onto the stack so kernel.caller works in the target.
    const callerName = this.handlerIdToName.get(callerHandlerId) ?? null;
    this.callerStack.push(callerName);

    this.callDepth++;
    let response: Uint8Array | null = null;
    try { response = this._invokeHandlerGetResponse(targetId, name, payload); }
    finally {
      this.callDepth--;
      this.callerStack.pop();
    }
    if (!response) return 0;
    if (response.length > caller.scratchSize) return -1;
    new Uint8Array(caller.memory.buffer, caller.scratch, response.length).set(response);
    return response.length;
  }

  /** Host import provided to dynamic handlers as `kernel.caller` (§4.2).
   *  Writes the **immediate** caller at outPtr as `[name_len u8][name ..]` and
   *  returns the total bytes written. No caller writes the single byte [0x00]
   *  (name_len = 0) and returns 1. The deeper chain is never exposed. */
  private _kernelCallerFromHandler(callerHandlerId: number, outPtr: number): number {
    const caller = this.wasmHandlers.get(callerHandlerId);
    if (!caller) return 0;
    const bytes = this._serializeImmediateCaller();
    if (outPtr + bytes.length > caller.memory.buffer.byteLength) return 0;
    new Uint8Array(caller.memory.buffer, outPtr, bytes.length).set(bytes);
    return bytes.length;
  }

  /** The genesis suite handler (algo_id 0x0000 = Ed25519 + SHA-3-256). Seeded
   *  by `registerSignature` at the genesis suite slot (§6.4) and reached like
   *  any ordinary handler, either by the signature module's suite dispatch or
   *  by a plain `kernel.call`. Standard scratch-ABI request/response (§6.6):
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

  /** Clear host-side index entries for a handler the kernel just removed. */
  private _dropHostMaps(name: Uint8Array): void {
    const key = nameKey(name);
    const hid = this.nameToHandlerId.get(key);
    if (hid !== undefined) {
      this.wasmHandlers.delete(hid);
      this.handlers.delete(hid);
      this.handlerIdToName.delete(hid);
      this.blockedFromCall.delete(hid);
    }
    this.nameToHandlerId.delete(key);
  }

  /** Derive the conventional slot name a suite for `algoId` is installed at
   *  (README §6.4): `genesisHash(SUITE_SLOT_PREFIX + algo_id_hex)`. A suite is
   *  an ordinary handler at this name — no registry, no separate ABI. */
  deriveSuiteSlotName(algoId: number): Uint8Array {
    return this.genesisHash(
      new TextEncoder().encode(SUITE_SLOT_PREFIX + algoIdHex(algoId)),
    );
  }

  /** Service the signature module's suite dispatch (§6.6). The module built the
   *  verify request at `[reqPtr, reqLen)` in bootstrap memory; the host derives
   *  the suite's slot name from `algoId` and hands the request to whatever
   *  ordinary handler is installed there. An unknown algo_id (no handler at the
   *  slot) or an unexpected response drops (returns 0), exactly as a suite that
   *  reports "invalid" — the fail-safe path (§6.4 lazy validation). */
  private _suiteVerify(algoId: number, reqPtr: number, reqLen: number): number {
    let req: Uint8Array;
    try { req = this.readFromBootstrap(reqPtr, reqLen); }
    catch { return 0; }
    const slotName = this.deriveSuiteSlotName(algoId);
    const hid = this.nameToHandlerId.get(nameKey(slotName));
    if (hid === undefined) return 0;
    const resp = this._invokeHandlerGetResponse(hid, slotName, req);
    return resp !== null && resp.length >= 1 && resp[0] === 1 ? 1 : 0;
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** The name of the **immediate** caller — the handler whose `kernel.call`
   *  reached the current one — or null when it was invoked directly from the
   *  pipeline (or by a host/guest-originated frame). Host-side equivalent of
   *  the kernel.caller WASM import (§4.2). Only the immediate caller is exposed;
   *  the deeper chain is deliberately unreachable so a bridge cannot authorize
   *  on a non-immediate frame (§9). */
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

  /** Read the current signer stack from bootstrap.wasm (§6.5). */
  get currentSigners(): readonly Signer[] {
    const count = this.bootstrapExports.get_signer_count();
    if (count === 0) return [];
    const result: Signer[] = [];
    for (let i = 0; i < count; i++) {
      const s = this._readSignerAt(i);
      if (s === null) continue;
      result.push({ algoId: s.algoId, publicKey: s.pubKey });
    }
    return result;
  }

  /** Host-level handler management (README §3.1). Installs or replaces a
   *  handler unconditionally. SetHandler-installed handlers are immune to
   *  installer state by construction (§9) — any matching install record
   *  is cleared as a side effect. */
  setHandler(name: Uint8Array, handlerId: number): void {
    const ptr = this.writeToKernel(name);
    try { this.kernelExports.set_handler(ptr, name.length, handlerId); }
    finally { this.kernelExports.dealloc(ptr); }
    const key = nameKey(name);
    this._displaceHandlerAtName(key, handlerId);
    this.nameToHandlerId.set(key, handlerId);
    this.handlerIdToName.set(handlerId, name.slice());
    // SetHandler entries are bootstrap-only by construction (§3.1) — clear
    // any stale install record at this slot so a future lookup can't return
    // stale data for brand-new bytes (§3.1 "Replacing installer-managed names").
    if (this._installer) this._installer._onKernelSlotMutated(name);
  }

  /** Remove a handler installed via setHandler (null handler case in §3.1). */
  removeHandler(name: Uint8Array): boolean {
    const ptr = this.writeToKernel(name);
    try {
      const ok = this.kernelExports.remove_handler(ptr, name.length) === 1;
      if (ok) {
        this._dropHostMaps(name);
        if (this._installer) this._installer._onKernelSlotMutated(name);
      }
      return ok;
    } finally { this.kernelExports.dealloc(ptr); }
  }

  /** Register the signature wrapper handler (§6.5) and seed the genesis suite
   *  (§6.2) at its slot. Required for any signed message to dispatch: the
   *  wrapper verifies via the suite installed at the algo's slot (§6.4), and the
   *  genesis suite (Ed25519 + SHA-3-256) is the one that must exist at boot.
   *  It is registered like any other bootstrap handler — a SetHandler-seeded
   *  slot with no install record, so the reference policy refuses to overlay it
   *  (§6.4) and the host retains it as the emergency-replacement path (§10.1). */
  registerSignature(signatureName: Uint8Array): void {
    this.setHandler(signatureName, HANDLER_SIGNATURE);
    this._signatureName = signatureName.slice();
    this.register(this.deriveSuiteSlotName(GENESIS_ALGO_ID), this._genesisSuiteHandler);
  }

  /** Register the `signature.signer` query handler (§6.5). Any handler that
   *  wants to read the current signer stack via `kernel.call(signerQueryName, …)`
   *  needs this wired. Optional — the wrapper works without it; only apps
   *  that introspect the author of a dispatch require it. */
  registerSignerQuery(signerQueryName: Uint8Array): void {
    this.setHandler(signerQueryName, HANDLER_SIGNATURE_SIGNER);
  }

  /** Mark a handler as forbidden from `kernel.call` (README §4.4). Use this
   *  for any deployer-added handler that calls `kernel.SetHandler` internally
   *  or that re-dispatches under a new author. The bootstrap signature wrapper
   *  is blocked by construction; the installer is blocked when registerInstaller
   *  runs. Idempotent. */
  blockFromCall(handlerId: number): void {
    this.blockedFromCall.add(handlerId);
  }

  /** Register the Installer (README §7). Wires the (blocked) install message
   *  handler — the installer's whole wire surface. Install records are read
   *  host-side via `lookupInstall`; there is no `installer.lookup` /
   *  `installer.caps_of` query message (README §7.6). Without calling this, the
   *  deployment is frozen — no message-driven installs. Returns the Installer
   *  instance for further configuration. */
  registerInstaller(installName: Uint8Array): Installer {
    const ih = new Installer(this, installName);
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

  /** Test helper: read a byte range from a dynamic WASM handler's memory by
   *  name. */
  readDynamicHandlerMemory(name: Uint8Array, ptr: number, len: number): Uint8Array | null {
    const hid = this.nameToHandlerId.get(nameKey(name));
    if (hid === undefined) return null;
    const wasm = this.wasmHandlers.get(hid);
    if (!wasm) return null;
    return new Uint8Array(wasm.memory.buffer, ptr, len).slice();
  }

  /** Test helper: call an arbitrary `(): i32` export on a dynamic WASM handler. */
  callDynamicHandlerI32(name: Uint8Array, exportName: string): number | null {
    const hid = this.nameToHandlerId.get(nameKey(name));
    if (hid === undefined) return null;
    const wasm = this.wasmHandlers.get(hid);
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
    const hid = this.nameToHandlerId.get(nameKey(name));
    if (hid === undefined) return null;
    const wasm = this.wasmHandlers.get(hid);
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
    const hid = this.nameToHandlerId.get(nameKey(name));
    if (hid === undefined) return null;
    // Same guards as the kernel.call router (§4.4): a handler the router would
    // refuse (signature wrapper, installer, deployer-blocked mutators) must not
    // become reachable by name through this host-side path either.
    if (this.blockedFromCall.has(hid)) return null;
    if (this.callDepth >= MAX_CALL_DEPTH) return null;
    // Push an anonymous caller frame so the target (and any bridge doing the
    // §9 caller-pinning check) sees "no installed caller" rather than a stale
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
    const ptr = this.writeToKernel(name);
    try { this.kernelExports.set_handler(ptr, name.length, id); }
    finally { this.kernelExports.dealloc(ptr); }

    const key = nameKey(name);
    this._displaceHandlerAtName(key, id);

    this.handlers.set(id, handler);
    this.nameToHandlerId.set(key, id);
    this.handlerIdToName.set(id, name.slice());
    if (this._installer) this._installer._onKernelSlotMutated(name);
    return id;
  }

  isRegistered(name: Uint8Array): boolean {
    const ptr = this.writeToKernel(name);
    try { return this.kernelExports.is_registered(ptr, name.length) === 1; }
    finally { this.kernelExports.dealloc(ptr); }
  }

  get handlerCount(): number {
    return this.kernelExports.handler_count();
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

  /** Derive a bootstrap name: SHA-3-256("seedkernel.bootstrap.v1:" + canonical).
   *  Use this for bootstrap handler names per §5.1. */
  deriveBootstrapName(canonical: string): Uint8Array {
    return this.sodium.crypto_hash_sha3256(
      new TextEncoder().encode("seedkernel.bootstrap.v1:" + canonical),
    );
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
   *  the §2.2 64 KB limit on decode. */
  encodeEnvelope(version: number, name: Uint8Array, payload: Uint8Array): Uint8Array {
    if (name.length === 0 || name.length > 255) throw new Error("encodeEnvelope: name length must be 1..255");
    const total = 4 + name.length + payload.length;
    if (total > MAX_ENVELOPE_BYTES) throw new Error("encodeEnvelope: envelope exceeds 64 KB");
    const out = new Uint8Array(total);
    out[0] = (MAGIC >> 8) & 0xff;
    out[1] = MAGIC & 0xff;
    out[2] = version;
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

    return this.encodeEnvelope(CURRENT_VERSION, this._signatureName, wrapperPayload);
  }

  /** Convenience: encode an inner envelope then wrap + sign it. */
  wrapAndEncode(
    privateKey: Uint8Array, publicKey: Uint8Array,
    version: number,
    name: Uint8Array, payload: Uint8Array
  ): Uint8Array {
    const innerBytes = this.encodeEnvelope(version, name, payload);
    return this.wrap(privateKey, publicKey, innerBytes);
  }
}
