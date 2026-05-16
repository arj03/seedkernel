// Host driver that loads kernel.wasm + bootstrap.wasm and wires them together.
//
// The host is the orchestrator:
//   - Provides libsodium Ed25519 + SHA-3-256 to bootstrap.wasm
//   - Routes invoke_handler callbacks from kernel.wasm to bootstrap.wasm handlers
//     or host-side JS handlers
//   - Drives the signature push/pop lifecycle (§6.5):
//       1. kernel invokes HANDLER_SIGNATURE
//       2. host calls bootstrap.handle_signature() → returns 1 if verified
//       3. host reads inner bytes from bootstrap memory, dispatches through kernel
//       4. host calls bootstrap.pop_signer() after inner dispatch returns
//   - Manages pluggable algorithm suite WASM modules (§6.1)
//   - Maintains the handler→declared-caps index used by capability.of_handler
//     and bridge caller-cap checks (README §8)
//   - Provides kernel.call and kernel.caller imports to dynamic handlers (§4.2, §4.4)
//   - Exposes the primitives the optional install handler (README §3.2)
//     consumes: installWasmHandler, isTrustedByCurrentSigners, currentTopSigner,
//     and a trust-revocation listener registry. The install handler itself
//     lives in install-handler.ts.

// No environment-specific imports here. The host runs anywhere with a
// WebAssembly engine: the caller supplies the kernel/bootstrap WASM bytes,
// and an initialized libsodium instance for ed25519 + SHA-3-256. Node and
// browser entry points (host/node.ts, host/browser.ts) wire the I/O.

import { MAGIC, CURRENT_VERSION, MAX_ENVELOPE_BYTES } from "./envelope.js";
import { InstallHandler } from "./install-handler.js";

type Sodium = typeof import("libsodium-wrappers");

export const GENESIS_ALGO_ID        = 0x0000;
export const GENESIS_PUBKEY_LEN     = 32;
export const GENESIS_SIGNATURE_LEN  = 64;
export const GENESIS_SECRET_KEY_LEN = 64;

export interface Signer {
  algoId: number;
  publicKey: Uint8Array;
}

export type Handler = (
  schemaId: Uint8Array,
  payload: Uint8Array,
  host: KernelHost
) => Uint8Array | void | null;

/** Install-approval callback (README §3.2). Called by the install handler
 *  after the trust prefilter accepts. Receives the target schema_id, the
 *  declared capabilities, the top signer, and the genesis-suite hash of
 *  the WASM bytes being installed. The hash lets the operator distinguish
 *  "this is the binary we audited" from "this is some other binary signed
 *  by the same key" without having to re-hash the bytes themselves.
 *  Return true to install, false to drop. The deployer wires this to
 *  whatever policy fits — interactive prompt, M-of-N quorum, allowlist,
 *  HSM, etc. With no callback wired, every install is dropped. */
export type ApproveInstall = (
  schemaId: Uint8Array,
  declaredCaps: readonly Uint8Array[],
  signer: Signer,
  wasmHash: Uint8Array,
) => boolean;

// ─── kernel.wasm exports ─────────────────────────────────────────────────

interface KernelExports {
  memory: WebAssembly.Memory;
  alloc(size: number): number;
  dealloc(ptr: number): void;
  set_handler(schemaPtr: number, schemaLen: number, handlerId: number): void;
  remove_handler(schemaPtr: number, schemaLen: number): number;
  is_registered(schemaPtr: number, schemaLen: number): number;
  handler_count(): number;
  dispatch(bytesPtr: number, bytesLen: number, ctx: number): void;
}

// ─── bootstrap.wasm exports ──────────────────────────────────────────────

interface BootstrapExports {
  memory: WebAssembly.Memory;
  alloc(size: number): number;
  dealloc(ptr: number): void;
  // Signature handler — returns 1 if verified (signer pushed, inner bytes ready)
  handle_signature(payloadPtr: number, payloadLen: number): number;
  get_inner_ptr(): number;
  get_inner_len(): number;
  pop_signer(): void;
  get_signer_count(): number;
  read_signer(index: number, outAlgoPtr: number, outPubPtr: number, outPubMaxLen: number): number;
  signer_pubkey_len(index: number): number;
  // Trust handler
  handle_trust_grant(payloadPtr: number, payloadLen: number): void;
  set_trust_grant_id(ptr: number, len: number): void;
  // Signature register handler (§6.4)
  handle_signature_register(payloadPtr: number, payloadLen: number): void;
  set_sig_register_id(ptr: number, len: number): void;
  // Trust table
  is_trusted(
    algoId: number,
    pubPtr: number, pubLen: number,
    schemaPtr: number, schemaLen: number
  ): number;
  is_trusted_by_current_signers(schemaPtr: number, schemaLen: number): number;
  trust_grant(
    algoId: number,
    pubPtr: number, pubLen: number,
    schemaPtr: number, schemaLen: number,
    granterAlgoId: number,
    granterPubPtr: number, granterPubLen: number
  ): number;
  trust_revoke(
    algoId: number,
    pubPtr: number, pubLen: number,
    schemaPtr: number, schemaLen: number
  ): void;
}

// ─── pluggable suite WASM contract (README §6.6) ─────────────────────────

interface SuiteInstance {
  memory: WebAssembly.Memory;
  alloc(size: number): number;
  dealloc(ptr: number): void;
  verify(pubPtr: number, pubLen: number, sigPtr: number, sigLen: number, dataPtr: number, dataLen: number): number;
  hash(dataPtr: number, dataLen: number, outPtr: number): number;
  // Reused buffers in the suite's linear memory. Allocated once at registration
  // (pub/sig sized from suite metadata) and grown on demand for data, so each
  // verify is a copy + call instead of three alloc/copy/dealloc round-trips.
  pubScratch: number;
  sigScratch: number;
  dataScratch: number;
  dataScratchSize: number;
}

// ─── handler routing ─────────────────────────────────────────────────────

const HANDLER_SIGNATURE             = -1;
const HANDLER_TRUST_GRANT           = -2;
const HANDLER_SIGNATURE_SIGNER      = -3;
const HANDLER_SIGNATURE_REGISTER    = -4;
const HANDLER_CAPABILITY_OF_HANDLER = -5;

const MAX_CALL_DEPTH = 8;

// Default scratch size mirrored by the host — handlers must reserve at
// least this much I/O space at their `scratch` offset (README §4.1).
const DEFAULT_SCRATCH_SIZE = 0x20000; // 128 KB

interface WasmHandlerRef {
  memory: WebAssembly.Memory;
  scratch: number;       // byte offset read from the handler's `scratch` global export
  scratchSize: number;   // bytes the host promises not to write past
  handle: (input_len: number) => number;
  exports: WebAssembly.Exports;
}

function schemaKey(schemaId: Uint8Array): string {
  let s = "";
  for (let i = 0; i < schemaId.length; i++) s += schemaId[i].toString(16).padStart(2, "0");
  return s;
}

/** Write a u32 in big-endian order at out[offset..offset+4]. Shared by the
 *  payload-encoding helpers that prepend a §4.4 replay-protection seq. */
export function writeU32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset]     = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>>  8) & 0xff;
  out[offset + 3] =  value         & 0xff;
}

/** Read a u32 in big-endian order from buf[offset..offset+4]. Mirror of
 *  writeU32BE; used by the install handler to consume the §4.4 seq prefix. */
export function readU32BE(buf: Uint8Array, offset: number): number {
  return ((buf[offset] << 24) | (buf[offset + 1] << 16) |
          (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
}

export class KernelHost {
  private kernelExports!: KernelExports;
  private bootstrapExports!: BootstrapExports;
  private sodium!: Sodium;
  private handlers = new Map<number, Handler>();
  private wasmHandlers = new Map<number, WasmHandlerRef>();
  private schemaToHandlerId = new Map<string, number>();
  private handlerIdToSchema = new Map<number, Uint8Array>();
  // Per-handler capability index: schemaKey → caps declared at install time.
  // Populated by installWasmHandler (called from the install handler);
  // never populated by setHandler entries.
  private handlerCapIndex = new Map<string, Uint8Array[]>();
  private suiteRegistry = new Map<number, SuiteInstance>();
  private nextHandlerId = 1;
  private callDepth = 0;
  // Call-chain tracking for kernel.caller (§4.2): top = direct caller's schema_id.
  private callerStack: (Uint8Array | null)[] = [];
  // Trust-revocation listeners fired by _onTrustRevoked (README §7.3). The
  // install handler wires its RevokeInstallsBy in via addOnRevoked.
  private revokeListeners: Array<(algoId: number, pubKey: Uint8Array, schemaId: Uint8Array) => void> = [];
  // Handler IDs that kernel.call must refuse (README §4.4). Bootstrap
  // mutating handlers (signature wrapper, trust.grant, signature.register)
  // are blocked by their fixed sentinel IDs; the install handler's positive
  // ID is added when registerInstallHandler runs.
  private blockedFromCall = new Set<number>([
    HANDLER_SIGNATURE,
    HANDLER_TRUST_GRANT,
    HANDLER_SIGNATURE_REGISTER,
  ]);
  // schema_id used to build outer signature envelopes in wrap(). Set by
  // registerSignature; null until then.
  private _signatureId: Uint8Array | null = null;
  // The single install handler instance, if registerInstallHandler was called.
  // Held so setApproveInstall can delegate to it.
  private _installHandler: InstallHandler | null = null;

  private constructor() {}

  /** Instantiate the kernel + bootstrap modules from in-memory bytes.
   *  The caller is responsible for sourcing the bytes (fs / fetch / inline)
   *  and for `await sodium.ready` before invoking — keeping this entry point
   *  free of Node- or browser-specific I/O is what lets the same host run
   *  in Node, browsers, Deno, Bun, workers, etc. The thin entry points in
   *  `node.ts` / `browser.ts` package the loading dance for each platform. */
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
          schemaPtr: number,
          schemaLen: number,
          payloadPtr: number,
          payloadLen: number,
          ctx: number
        ) => {
          host._onInvokeHandler(handlerId, schemaPtr, schemaLen, payloadPtr, payloadLen, ctx);
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

    // ── load bootstrap.wasm ───────────────────────────────────────────
    const bootstrapImports: WebAssembly.Imports = {
      env: {
        ed25519_verify: (pubPtr: number, sigPtr: number, dataPtr: number, dataLen: number): number => {
          return host._ed25519Verify(pubPtr, sigPtr, dataPtr, dataLen);
        },
        on_trust_revoked: (
          algoId: number,
          pubPtr: number, pubLen: number,
          schemaPtr: number, schemaLen: number
        ) => {
          host._onTrustRevoked(algoId, pubPtr, pubLen, schemaPtr, schemaLen);
        },
        // Pluggable suite host imports (§6.1). Called by bootstrap.wasm when a
        // non-genesis algorithm suite is registered or used.
        suite_register: (
          algoId: number,
          pubkeyLen: number, sigMaxLen: number, hashLen: number,
          wasmPtr: number, wasmLen: number
        ): number => {
          return host._suiteRegister(algoId, pubkeyLen, sigMaxLen, hashLen, wasmPtr, wasmLen);
        },
        suite_verify: (
          algoId: number,
          pubPtr: number, pubLen: number,
          sigPtr: number, sigLen: number,
          dataPtr: number, dataLen: number
        ): number => {
          return host._suiteVerify(algoId, pubPtr, pubLen, sigPtr, sigLen, dataPtr, dataLen);
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

  private writeToBootstrap(data: Uint8Array): number {
    const ptr = this.bootstrapExports.alloc(data.length);
    new Uint8Array(this.bootstrapExports.memory.buffer, ptr, data.length).set(data);
    return ptr;
  }

  private readFromBootstrap(ptr: number, len: number): Uint8Array {
    return new Uint8Array(this.bootstrapExports.memory.buffer, ptr, len).slice();
  }

  /** Allocate in bootstrap memory and copy len bytes from kernel memory at
   *  srcPtr → bootstrap[ret..ret+len]. Skips the JS intermediate buffer that
   *  the readFrom/writeTo combo used to allocate per call. Caller deallocates. */
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

  /** Pass a schema_id into one of bootstrap.wasm's `set_*_id` exports —
   *  alloc, copy, call, dealloc. Used by the registerSignature/TrustGrant/
   *  SignatureRegister entry points. */
  private _setBootstrapId(setter: (ptr: number, len: number) => void, id: Uint8Array): void {
    const ptr = this.writeToBootstrap(id);
    try { setter(ptr, id.length); }
    finally { this.bootstrapExports.dealloc(ptr); }
  }

  /** When a schema_id is being rebound to a new handlerId, drop the old
   *  handler's host-side state. Kernel-side replacement is done separately
   *  by the kernel.wasm set_handler call. */
  private _displaceHandlerAtSchema(key: string, newId: number): void {
    const oldId = this.schemaToHandlerId.get(key);
    if (oldId !== undefined && oldId !== newId) {
      this.wasmHandlers.delete(oldId);
      this.handlers.delete(oldId);
      this.handlerIdToSchema.delete(oldId);
    }
  }

  // ─── import implementations ──────────────────────────────────────────

  /** Called by kernel.wasm when a handler matches (§3). */
  private _onInvokeHandler(
    handlerId: number,
    schemaPtr: number,
    schemaLen: number,
    payloadPtr: number,
    payloadLen: number,
    _ctxId: number
  ): void {
    if (handlerId === HANDLER_SIGNATURE) {
      // Copy payload directly from kernel to bootstrap memory — skip the JS
      // intermediate slice. alloc happens on the destination first, then a
      // single TypedArray.set covers the byte transfer (browser/V8 ≈ memcpy).
      const payPtr = this._copyKernelToBootstrap(payloadPtr, payloadLen);
      let verified = 0;
      try {
        // Catch any throw out of bootstrap.wasm (e.g. heap OOM under flood)
        // and treat it as "verify failed" rather than letting it unwind out
        // of the dispatch path and crash the host.
        try { verified = this.bootstrapExports.handle_signature(payPtr, payloadLen); }
        catch { verified = 0; }
      } finally {
        this.bootstrapExports.dealloc(payPtr);
      }
      if (!verified) return;

      // From here on the signer is on the bootstrap stack. Any throw before
      // pop_signer runs would leak the signer and let an unrelated later
      // message impersonate this one — wrap everything in a single finally.
      let kPtr = 0;
      try {
        const innerLen = this.bootstrapExports.get_inner_len();
        const innerPtr = this.bootstrapExports.get_inner_ptr();
        kPtr = this._copyBootstrapToKernel(innerPtr, innerLen);
        // A throw out of the inner dispatch (recursive handle_signature OOM,
        // a buggy WASM handler, etc.) is dropped here so the outer pipeline
        // still pops the signer cleanly.
        try { this.kernelExports.dispatch(kPtr, innerLen, _ctxId); }
        catch { /* drop — pop_signer in finally restores the stack */ }
      } finally {
        if (kPtr) this.kernelExports.dealloc(kPtr);
        this.bootstrapExports.pop_signer();
      }
      return;
    }

    if (handlerId === HANDLER_TRUST_GRANT) {
      // handle_trust_grant checks trust internally (signer stack + trust table).
      const payPtr = this._copyKernelToBootstrap(payloadPtr, payloadLen);
      try {
        // Drop on any throw out of bootstrap.
        try { this.bootstrapExports.handle_trust_grant(payPtr, payloadLen); }
        catch { /* drop */ }
      } finally {
        this.bootstrapExports.dealloc(payPtr);
      }
      return;
    }

    if (handlerId === HANDLER_SIGNATURE_REGISTER) {
      // handle_signature_register checks trust internally (§6.4).
      const payPtr = this._copyKernelToBootstrap(payloadPtr, payloadLen);
      try {
        // Drop on any throw out of bootstrap.
        try { this.bootstrapExports.handle_signature_register(payPtr, payloadLen); }
        catch { /* drop */ }
      } finally {
        this.bootstrapExports.dealloc(payPtr);
      }
      return;
    }

    // Dynamic WASM handler or host-JS handler — response is dropped for
    // inbound dispatch. kernel.call is the path that surfaces responses.
    const schemaId = this.readFromKernel(schemaPtr, schemaLen);
    const payload = this.readFromKernel(payloadPtr, payloadLen);
    this._invokeHandlerGetResponse(handlerId, schemaId, payload);
  }

  /** Core invocation used both by inbound dispatch (response dropped) and by
   *  kernel.call (response returned to caller). Returns the handler's response
   *  bytes, or null if no response / no handler. */
  private _invokeHandlerGetResponse(
    handlerId: number,
    schemaId: Uint8Array,
    payload: Uint8Array
  ): Uint8Array | null {
    if (handlerId === HANDLER_SIGNATURE_SIGNER) {
      return this._serializeSignerStack();
    }

    if (handlerId === HANDLER_CAPABILITY_OF_HANDLER) {
      return this._handleCapabilityOfHandler(payload);
    }

    const wasm = this.wasmHandlers.get(handlerId);
    if (wasm) {
      // Scratch-region contract (README §4): write input at the handler's
      // scratch offset, call handle(input_len), read response from the
      // same offset. No allocator involved.
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
      // Treat a JS handler the same as a WASM handler: an exception aborts
      // the call but must not unwind through dispatch and corrupt the
      // signer stack or kernel state above it.
      try {
        const r = handler(schemaId, payload, this);
        return r instanceof Uint8Array ? r : null;
      } catch {
        return null;
      }
    }
    return null;
  }

  /** capability.of_handler query handler (README §8.2).
   *  Payload: [schema_id_len u8][schema_id ..]
   *  Response: [count u8][cap_id_len u8][cap_id ..]* */
  private _handleCapabilityOfHandler(payload: Uint8Array): Uint8Array {
    if (payload.length < 1) return new Uint8Array([0]);
    const sidLen = payload[0];
    if (payload.length < 1 + sidLen) return new Uint8Array([0]);
    const schemaId = payload.slice(1, 1 + sidLen);
    const caps = this.handlerCapIndex.get(schemaKey(schemaId));
    if (!caps) return new Uint8Array([0]);
    let size = 1;
    for (const cap of caps) size += 1 + cap.length;
    const out = new Uint8Array(size);
    let o = 0;
    out[o++] = caps.length;
    for (const cap of caps) {
      out[o++] = cap.length;
      out.set(cap, o);
      o += cap.length;
    }
    return out;
  }

  /** Instantiate a dynamic WASM handler and install it via SetHandler.
   *  Used by the install handler (README §3.2 step 5–7) to do the WASM-side
   *  work that no module on its own can do (instantiating WASM is a host
   *  capability). The install handler is responsible for the trust prefilter,
   *  approveInstall callback, replacement policy, and recording installer
   *  attribution; this method just turns "here are the bytes" into "the
   *  module is now wired to the kernel and the cap index has the right row".
   *  Returns true on success, false on any failure (instantiation error,
   *  missing exports, scratch out of range). */
  installWasmHandler(
    targetSchemaId: Uint8Array,
    declaredCaps: readonly Uint8Array[],
    wasmBytes: Uint8Array,
  ): boolean {
    if (targetSchemaId.length === 0) return false;
    if (wasmBytes.length === 0) return false;

    const handlerId = this.nextHandlerId++;
    // Use a ref-wrapper so kernel.caller can access the handler's memory after
    // the instance is created (memory isn't available until after instantiation).
    const memRef = { memory: null as WebAssembly.Memory | null };
    let instance: WebAssembly.Instance;
    try {
      const mod = new WebAssembly.Module(wasmBytes as BufferSource);
      const imports: WebAssembly.Imports = {
        kernel: {
          call: (schPtr: number, schLen: number, plPtr: number, plLen: number): number =>
            this._kernelCallFromHandler(handlerId, schPtr, schLen, plPtr, plLen),
          caller: (outPtr: number): number => {
            if (!memRef.memory || this.callerStack.length === 0) return 0;
            const callerSchemaId = this.callerStack[this.callerStack.length - 1];
            if (!callerSchemaId) return 0;
            new Uint8Array(memRef.memory.buffer, outPtr, callerSchemaId.length).set(callerSchemaId);
            return callerSchemaId.length;
          },
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
      handle?: (input_len: number) => number;
    };
    if (!exps.memory || !(exps.scratch instanceof WebAssembly.Global) || typeof exps.handle !== "function") return false;
    memRef.memory = exps.memory; // wire kernel.caller after instantiation
    const scratchOffset = exps.scratch.value as number;
    if (typeof scratchOffset !== "number" || scratchOffset <= 0 || scratchOffset + DEFAULT_SCRATCH_SIZE > exps.memory.buffer.byteLength) return false;

    // SetHandler is unconditional at the kernel level — replace whatever is
    // there. The install handler's replacement policy is applied before this
    // method is called.
    const kPtr = this.writeToKernel(targetSchemaId);
    try {
      this.kernelExports.set_handler(kPtr, targetSchemaId.length, handlerId);
    } finally {
      this.kernelExports.dealloc(kPtr);
    }

    const targetKey = schemaKey(targetSchemaId);
    this._displaceHandlerAtSchema(targetKey, handlerId);

    this.wasmHandlers.set(handlerId, {
      memory: exps.memory,
      scratch: scratchOffset,
      scratchSize: DEFAULT_SCRATCH_SIZE,
      handle: exps.handle,
      exports: instance.exports,
    });

    this.schemaToHandlerId.set(targetKey, handlerId);
    this.handlerIdToSchema.set(handlerId, targetSchemaId.slice());
    this.handlerCapIndex.set(targetKey, declaredCaps.map((c) => c.slice()));
    return true;
  }

  /** Check whether the top signer on the bootstrap signer stack is trusted
   *  for the given schema_id. Used by the install handler (README §3.2 step 2)
   *  and by any other handler that gates on signer-side trust. */
  isTrustedByCurrentSigners(schemaId: Uint8Array): boolean {
    const ptr = this.writeToBootstrap(schemaId);
    try {
      return this.bootstrapExports.is_trusted_by_current_signers(ptr, schemaId.length) === 1;
    } finally {
      this.bootstrapExports.dealloc(ptr);
    }
  }

  /** Top-of-stack signer, or null if the signer stack is empty. */
  get currentTopSigner(): Signer | null {
    const s = this._readTopSigner();
    if (!s) return null;
    return { algoId: s.algoId, publicKey: s.pubKey };
  }

  /** Subscribe to trust-revocation events (README §7.3 OnRevoked cascade).
   *  The install handler wires its RevokeInstallsBy in via this hook so that
   *  revoking a key removes the handlers that key installed. Listeners run
   *  in registration order; exceptions are swallowed so one buggy listener
   *  doesn't block the rest of the cascade.
   *
   *  The install handler's RevokeInstallsBy *removes the kernel handler 
   *  synchronously*, which clears the matching capability-index row inline. 
   *  Listeners registered after registerInstallHandler will therefore see 
   *  the post-removal state when they query (e.g. `getHandlerDeclaredCaps` 
   *  returns []). If a listener needs to query state about the handler 
   *  being torn down - for instance to record audit metadata before it
   *  disappears - register it BEFORE registerInstallHandler. */
  addOnRevoked(callback: (algoId: number, pubKey: Uint8Array, schemaId: Uint8Array) => void): void {
    this.revokeListeners.push(callback);
  }

  /** Read signer at index, sizing the pubkey buffer to the suite's actual
   *  pubkey length so post-quantum keys are not truncated. Returns null on
   *  out-of-range index. */
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

  /** Read the top-of-stack signer from bootstrap.wasm. Returns null if the
   *  signer stack is empty (unsigned message path). */
  private _readTopSigner(): { algoId: number; pubKey: Uint8Array } | null {
    const count = this.bootstrapExports.get_signer_count();
    if (count === 0) return null;
    return this._readSignerAt(count - 1);
  }

  /** Host import provided to dynamic handlers as `kernel.call` (README §4.4).
   *  Looks up the target handler, invokes it synchronously, and writes the
   *  response back into the caller's scratch region. Returns the response
   *  length, 0 if no response, or -1 on error (no handler / depth exceeded /
   *  response too large). The caller's scratch is overwritten unconditionally. */
  private _kernelCallFromHandler(
    callerHandlerId: number,
    schemaPtr: number, schemaLen: number,
    payloadPtr: number, payloadLen: number
  ): number {
    if (this.callDepth >= MAX_CALL_DEPTH) return -1;
    const caller = this.wasmHandlers.get(callerHandlerId);
    if (!caller) return -1;
    const schemaId = new Uint8Array(caller.memory.buffer, schemaPtr, schemaLen).slice();
    const payload = new Uint8Array(caller.memory.buffer, payloadPtr, payloadLen).slice();
    const targetId = this.schemaToHandlerId.get(schemaKey(schemaId));
    if (targetId === undefined) return -1;
    // Bootstrap mutating handlers (signature wrapper, trust.grant,
    // signature.register, install) run only at top-level dispatch where
    // the signature wrapper has already been verified. Allowing them via
    // kernel.call would let an in-handler call mutate trust/signature/install
    // state under the current signer's authority without that signer's intent
    // (README §4.4). Return -1 so the failure is observable.
    if (this.blockedFromCall.has(targetId)) return -1;

    // Push caller schema onto the stack so kernel.caller works in the target.
    const callerSchemaId = this.handlerIdToSchema.get(callerHandlerId) ?? null;
    this.callerStack.push(callerSchemaId);

    this.callDepth++;
    let response: Uint8Array | null = null;
    try { response = this._invokeHandlerGetResponse(targetId, schemaId, payload); }
    finally {
      this.callDepth--;
      this.callerStack.pop();
    }
    if (!response) return 0;
    if (response.length > caller.scratchSize) return -1;
    new Uint8Array(caller.memory.buffer, caller.scratch, response.length).set(response);
    return response.length;
  }

  /** Serialize the current signer stack as
   *  `[count u8][algo_id u16 BE][pubkey_len u16 BE][pubkey ..]*` — the format
   *  the `signature.signer` handler returns to callers of kernel.call (§6.5).
   *
   *  pubkey_len is u16 BE so post-quantum suites with multi-kilobyte public
   *  keys (ML-DSA-87 = 2592 bytes) fit without truncation. The count byte
   *  remains u8 since MAX_SIGNATURE_DEPTH = 4. */
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

  /** Ed25519 verify — reads from bootstrap.wasm memory, calls libsodium. */
  private _ed25519Verify(pubPtr: number, sigPtr: number, dataPtr: number, dataLen: number): number {
    try {
      const mem  = this.bootstrapExports.memory.buffer;
      const pub  = new Uint8Array(mem, pubPtr,  32);
      const sig  = new Uint8Array(mem, sigPtr,  64);
      const data = new Uint8Array(mem, dataPtr, dataLen);
      return this.sodium.crypto_sign_verify_detached(sig, data, pub) ? 1 : 0;
    } catch { return 0; }
  }

  /** Revocation callback — called by bootstrap.wasm during the trust cascade
   *  (README §7.3). Each registered listener (notably the install handler's
   *  RevokeInstallsBy) decides whether to act on this (algoId, pubKey, schemaId).
   *  Listener exceptions are swallowed so one buggy listener can't block the
   *  rest of the cascade. */
  private _onTrustRevoked(
    algoId: number,
    pubPtr: number, pubLen: number,
    schemaPtr: number, schemaLen: number
  ): void {
    const schemaId = this.readFromBootstrap(schemaPtr, schemaLen);
    const pubKey   = this.readFromBootstrap(pubPtr, pubLen);
    for (const cb of this.revokeListeners) {
      try { cb(algoId, pubKey, schemaId); } catch { /* swallow */ }
    }
  }

  /** Clear host-side index entries for a handler the kernel just removed. */
  private _dropHostMaps(schemaId: Uint8Array): void {
    const key = schemaKey(schemaId);
    const hid = this.schemaToHandlerId.get(key);
    if (hid !== undefined) {
      this.wasmHandlers.delete(hid);
      this.handlers.delete(hid);
      this.handlerIdToSchema.delete(hid);
      this.blockedFromCall.delete(hid);
    }
    this.schemaToHandlerId.delete(key);
    this.handlerCapIndex.delete(key);
  }

  /** Load and instantiate a pluggable algorithm suite WASM module (§6.1).
   *  Called from bootstrap.wasm via the suite_register host import. */
  private _suiteRegister(
    algoId: number,
    pubkeyLen: number, sigMaxLen: number, _hashLen: number,
    wasmPtr: number, wasmLen: number
  ): number {
    // Defense in depth: bootstrap.wasm already checks hasSuiteMeta before
    // calling here. Refuse a duplicate so the two registries cannot diverge
    // even if a future caller bypasses bootstrap's check.
    if (this.suiteRegistry.has(algoId)) return 0;
    const wasmBytes = this.readFromBootstrap(wasmPtr, wasmLen);
    try {
      const mod = new WebAssembly.Module(wasmBytes as BufferSource);
      const suiteImports: WebAssembly.Imports = {
        env: {
          abort: (_m: number, _f: number, l: number, c: number) => {
            throw new Error(`suite abort at ${l}:${c}`);
          },
        },
      };
      const instance = new WebAssembly.Instance(mod, suiteImports);
      const exps = instance.exports as {
        memory?: WebAssembly.Memory;
        alloc?: (size: number) => number;
        dealloc?: (ptr: number) => void;
        verify?: (pubPtr: number, pubLen: number, sigPtr: number, sigLen: number, dataPtr: number, dataLen: number) => number;
        hash?: (dataPtr: number, dataLen: number, outPtr: number) => number;
      };
      if (!exps.memory || typeof exps.alloc !== "function" || typeof exps.verify !== "function") return 0;
      const alloc = exps.alloc;
      // Pre-allocate the per-call buffers once; the data buffer starts small
      // and grows on demand in _suiteVerify (most signed envelopes are <1 KB).
      const INITIAL_DATA_SCRATCH = 4096;
      this.suiteRegistry.set(algoId, {
        memory: exps.memory,
        alloc,
        dealloc: exps.dealloc ?? (() => {}),
        verify: exps.verify,
        hash: exps.hash ?? ((_dp: number, _dl: number, _op: number) => 0),
        pubScratch:  alloc(pubkeyLen),
        sigScratch:  alloc(sigMaxLen),
        dataScratch: alloc(INITIAL_DATA_SCRATCH),
        dataScratchSize: INITIAL_DATA_SCRATCH,
      });
      return 1;
    } catch {
      return 0;
    }
  }

  /** Call a registered suite's verify function (§6.6).
   *  Called from bootstrap.wasm via the suite_verify host import.
   *  All pointers are into bootstrap.wasm's linear memory. */
  private _suiteVerify(
    algoId: number,
    pubPtr: number, pubLen: number,
    sigPtr: number, sigLen: number,
    dataPtr: number, dataLen: number
  ): number {
    const suite = this.suiteRegistry.get(algoId);
    if (!suite) return 0;
    // Grow the data scratch on demand (pub/sig are sized by suite metadata
    // at registration so they're already big enough for any valid input).
    if (dataLen > suite.dataScratchSize) {
      try { suite.dealloc(suite.dataScratch); } catch { /* swallow */ }
      suite.dataScratch = suite.alloc(dataLen);
      suite.dataScratchSize = dataLen;
    }
    // Copy directly from bootstrap memory into the suite's scratch — skip
    // the host-side intermediate Uint8Arrays.
    const bootMem = new Uint8Array(this.bootstrapExports.memory.buffer);
    const sMem    = new Uint8Array(suite.memory.buffer);
    sMem.set(bootMem.subarray(pubPtr,  pubPtr  + pubLen),  suite.pubScratch);
    sMem.set(bootMem.subarray(sigPtr,  sigPtr  + sigLen),  suite.sigScratch);
    sMem.set(bootMem.subarray(dataPtr, dataPtr + dataLen), suite.dataScratch);
    try {
      return suite.verify(
        suite.pubScratch,  pubLen,
        suite.sigScratch,  sigLen,
        suite.dataScratch, dataLen,
      );
    } catch {
      return 0;
    }
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** The schema_id of the handler that initiated the current kernel.call chain,
   *  or null when the current handler was invoked directly from the pipeline.
   *  This is the host-side equivalent of the kernel.caller WASM import (§4.2),
   *  available to host-JS bridge handlers that cannot declare WASM imports. */
  get currentCaller(): Uint8Array | null {
    if (this.callerStack.length === 0) return null;
    return this.callerStack[this.callerStack.length - 1] ?? null;
  }

  /** Return the capability IDs declared at install time by the handler
   *  registered under schemaId, or an empty array for unknown / bootstrap handlers.
   *  Bridge handlers use this together with currentCaller to enforce the §9
   *  caller-capability check without needing a kernel.call to capability.of_handler. */
  getHandlerDeclaredCaps(schemaId: Uint8Array): readonly Uint8Array[] {
    return this.handlerCapIndex.get(schemaKey(schemaId)) ?? [];
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

  /** Host-level handler management (README §3.1). Installs or replaces a handler
   *  unconditionally. Used for bootstrap handlers — installer attribution and
   *  capability index entries are not created for setHandler installs, so they
   *  are immune to revocation cascades by construction (§8.3). */
  setHandler(schemaId: Uint8Array, handlerId: number): void {
    const ptr = this.writeToKernel(schemaId);
    try { this.kernelExports.set_handler(ptr, schemaId.length, handlerId); }
    finally { this.kernelExports.dealloc(ptr); }
    const key = schemaKey(schemaId);
    this._displaceHandlerAtSchema(key, handlerId);
    this.schemaToHandlerId.set(key, handlerId);
    this.handlerIdToSchema.set(handlerId, schemaId.slice());
    // setHandler entries are bootstrap-only by construction (§3.1) — they
    // declare no caps, so capability.of_handler returns [0x00] for them.
    // Drop any stale cap-index entry left over from a prior dynamic install
    // at this schema. Installer attribution lives in the install handler's
    // own table, which the install handler clears via revokeInstallsBy when
    // the kernel slot is removed.
    this.handlerCapIndex.delete(key);
  }

  /** Remove a handler installed via setHandler (null handler case in §3.1). */
  removeHandler(schemaId: Uint8Array): boolean {
    const ptr = this.writeToKernel(schemaId);
    try {
      const ok = this.kernelExports.remove_handler(ptr, schemaId.length) === 1;
      if (ok) this._dropHostMaps(schemaId);
      return ok;
    } finally { this.kernelExports.dealloc(ptr); }
  }

  /** Register the signature wrapper handler and the signature.signer query
   *  handler (§6.5). Both must be registered for WASM handlers that query
   *  the signer stack via kernel.call to work correctly. */
  registerSignature(signatureId: Uint8Array, signerQueryId: Uint8Array): void {
    this.setHandler(signatureId, HANDLER_SIGNATURE);
    this.setHandler(signerQueryId, HANDLER_SIGNATURE_SIGNER);
    // Stash a copy so wrap() can use it as the outer schema_id (§6.3).
    this._signatureId = signatureId.slice();
  }

  /** Register the trust.grant handler — routes to bootstrap.wasm.
   *  Uses setHandler (§3.1, §8) and stores the schema_id in bootstrap.wasm for trust checking. */
  registerTrustGrant(trustGrantId: Uint8Array): void {
    this.setHandler(trustGrantId, HANDLER_TRUST_GRANT);
    this._setBootstrapId(this.bootstrapExports.set_trust_grant_id, trustGrantId);
  }

  /** Register the signature.register handler — routes to bootstrap.wasm (§6.4).
   *  Stores the schema_id in bootstrap.wasm so it can check signer trust before
   *  accepting a new algorithm suite. */
  registerSignatureRegister(sigRegId: Uint8Array): void {
    this.setHandler(sigRegId, HANDLER_SIGNATURE_REGISTER);
    this._setBootstrapId(this.bootstrapExports.set_sig_register_id, sigRegId);
  }

  /** Register the capability.of_handler query handler (README §8.2).
   *  Used by I/O bridges to look up the declared capabilities of their caller. */
  registerCapabilityOfHandler(capOfHandlerId: Uint8Array): void {
    this.setHandler(capOfHandlerId, HANDLER_CAPABILITY_OF_HANDLER);
  }

  /** Mark a handler as forbidden from `kernel.call` (README §4.4). Use this
   *  for any deployer-added handler that calls `kernel.SetHandler` internally
   *  — `bootstrap.replace` (§10.1) being the canonical example — so an
   *  in-handler `kernel.call` cannot mutate kernel state under the current
   *  signer's authority without that signer's explicit intent. The bootstrap
   *  mutating handlers (signature wrapper, trust.grant, signature.register,
   *  install) are blocked by construction; this method extends that protection
   *  to handlers the deployer wires post-bootstrap. Idempotent.
   *
   *  Removing the handler (via removeHandler or by being overwritten via
   *  setHandler) clears the block as a side effect — re-marking the new
   *  handler is the deployer's responsibility. */
  blockFromCall(handlerId: number): void {
    this.blockedFromCall.add(handlerId);
  }

  /** Register the install handler (README §3.2). Optional — without it, the
   *  deployment is frozen and no message-driven installs are possible. Wires
   *  a fresh InstallHandler at installSchemaId, blocks it from kernel.call,
   *  and subscribes its RevokeInstallsBy to the trust cascade. Returns the
   *  InstallHandler instance for further configuration (e.g. setApproveInstall). */
  registerInstallHandler(installSchemaId: Uint8Array): InstallHandler {
    const ih = new InstallHandler(this, installSchemaId);
    const id = this.register(installSchemaId, ih.handler);
    this.blockFromCall(id);
    this.addOnRevoked((algo, pk, sid) => ih.revokeInstallsBy(algo, pk, sid));
    this._installHandler = ih;
    return ih;
  }

  /** Convenience: wire the install-approval callback on the install handler
   *  registered via registerInstallHandler. Throws if no install handler has
   *  been registered yet. */
  setApproveInstall(callback: ApproveInstall | null): void {
    if (!this._installHandler) {
      throw new Error("setApproveInstall: registerInstallHandler must be called first");
    }
    this._installHandler.setApproveInstall(callback);
  }

  /** Build an install payload (README §3.2):
   *    [seq u32 BE][caps_count u8][caps...][target_schema_len u8][target_schema][wasm]
   *  Pass an empty caps array for pure-computation handlers (caps_count = 0).
   *
   *  `seq` is the §4.4 replay-protection sequence number for the signer
   *  (the key that will wrap this payload). The install handler tracks the
   *  high-water mark per (algoId, pubKey) and drops any payload with
   *  seq <= last_seen — including a wire-byte-identical replay of an
   *  install whose handler was later removed. */
  encodeInstallPayload(
    seq: number,
    caps: Uint8Array[],
    targetSchemaId: Uint8Array,
    wasmBytes: Uint8Array,
  ): Uint8Array {
    if (targetSchemaId.length === 0 || targetSchemaId.length > 255)
      throw new Error("encodeInstallPayload: target schema_id length must be 1..255");
    if (seq < 0 || seq > 0xffffffff)
      throw new Error("encodeInstallPayload: seq must fit in u32");
    let headerLen = 4;     // seq u32 BE
    headerLen += 1;        // caps_count byte
    for (const cap of caps) headerLen += 1 + cap.length;
    headerLen += 1 + targetSchemaId.length; // target_schema_len + target_schema
    const out = new Uint8Array(headerLen + wasmBytes.length);
    let o = 0;
    writeU32BE(out, o, seq); o += 4;
    out[o++] = caps.length;
    for (const cap of caps) {
      out[o++] = cap.length;
      out.set(cap, o);
      o += cap.length;
    }
    out[o++] = targetSchemaId.length;
    out.set(targetSchemaId, o); o += targetSchemaId.length;
    out.set(wasmBytes, o);
    return out;
  }

  /** Test helper: read a byte range from a dynamic WASM handler's memory by
   *  schema_id. Returns null if no dynamic handler is registered under that
   *  schema. */
  readDynamicHandlerMemory(schemaId: Uint8Array, ptr: number, len: number): Uint8Array | null {
    const hid = this.schemaToHandlerId.get(schemaKey(schemaId));
    if (hid === undefined) return null;
    const wasm = this.wasmHandlers.get(hid);
    if (!wasm) return null;
    return new Uint8Array(wasm.memory.buffer, ptr, len).slice();
  }

  /** Test helper: call an arbitrary `(): i32` export on a dynamic WASM handler. */
  callDynamicHandlerI32(schemaId: Uint8Array, exportName: string): number | null {
    const hid = this.schemaToHandlerId.get(schemaKey(schemaId));
    if (hid === undefined) return null;
    const wasm = this.wasmHandlers.get(hid);
    if (!wasm) return null;
    const fn = (wasm.exports as { [k: string]: unknown })[exportName];
    if (typeof fn !== "function") return null;
    return (fn as () => number)();
  }

  /** Call a named `(input_len: i32) => i32` (or void) export on a dynamic
   *  WASM handler, staging `payload` in scratch first. The pattern mirrors
   *  the kernel's `handle` invocation so deployers can drive one-shot
   *  configuration calls (or any other auxiliary export) without dispatching
   *  a synthetic envelope through the kernel.
   *
   *  Returns the export's i32 return value, or null if the handler is not
   *  registered, the export does not exist, or `payload` exceeds the
   *  handler's scratch region. Void-returning exports yield `undefined`. */
  callDynamicExport(
    schemaId: Uint8Array,
    exportName: string,
    payload: Uint8Array,
  ): number | null | undefined {
    const hid = this.schemaToHandlerId.get(schemaKey(schemaId));
    if (hid === undefined) return null;
    const wasm = this.wasmHandlers.get(hid);
    if (!wasm) return null;
    const fn = (wasm.exports as { [k: string]: unknown })[exportName];
    if (typeof fn !== "function") return null;
    if (payload.length > wasm.scratchSize) return null;
    new Uint8Array(wasm.memory.buffer, wasm.scratch, payload.length).set(payload);
    return (fn as (n: number) => number)(payload.length);
  }

  /** Register a host-side handler. Returns the assigned id. Unconditionally
   *  replaces whatever is at this schema_id (kernel-level setHandler is
   *  unconditional, README §3.1). Host-installed handlers have no installer
   *  attribution and are immune to revocation cascades. */
  register(schemaId: Uint8Array, handler: Handler): number {
    const id = this.nextHandlerId++;
    const ptr = this.writeToKernel(schemaId);
    try { this.kernelExports.set_handler(ptr, schemaId.length, id); }
    finally { this.kernelExports.dealloc(ptr); }

    const key = schemaKey(schemaId);
    this._displaceHandlerAtSchema(key, id);

    this.handlers.set(id, handler);
    this.schemaToHandlerId.set(key, id);
    this.handlerIdToSchema.set(id, schemaId.slice());
    // Host-installed JS handlers have no declared caps — drop any stale
    // cap-index entry left from a previous dynamic install at this slot.
    this.handlerCapIndex.delete(key);
    return id;
  }

  isRegistered(schemaId: Uint8Array): boolean {
    const ptr = this.writeToKernel(schemaId);
    try { return this.kernelExports.is_registered(ptr, schemaId.length) === 1; }
    finally { this.kernelExports.dealloc(ptr); }
  }

  get handlerCount(): number {
    return this.kernelExports.handler_count();
  }

  /** Feed raw envelope bytes into the pipeline. */
  dispatch(bytes: Uint8Array): void {
    // Pre-validate the §2.2 cap before allocating anything in kernel memory.
    // The kernel's own dispatch checks this too, but only after we've grown
    // its linear memory by `bytes.length` to copy the input - a flood of
    // oversize buffers would permanently bloat the WASM page count even
    // though every individual allocation is dealloc'd on return.
    if (bytes.length > MAX_ENVELOPE_BYTES) return;
    // Drop on any throw out of the kernel pipeline - a single bad
    // message must not bring down the host loop.
    const ptr = this.writeToKernel(bytes);
    try {
      try { this.kernelExports.dispatch(ptr, bytes.length, 0); }
      catch { /* drop */ }
    } finally { this.kernelExports.dealloc(ptr); }
  }

  /** Check trust — delegates to bootstrap.wasm. */
  isTrusted(algoId: number, publicKey: Uint8Array, schemaId: Uint8Array): boolean {
    const pubPtr    = this.writeToBootstrap(publicKey);
    const schemaPtr = this.writeToBootstrap(schemaId);
    try {
      return this.bootstrapExports.is_trusted(algoId, pubPtr, publicKey.length,
                                           schemaPtr, schemaId.length) === 1;
    } finally {
      this.bootstrapExports.dealloc(pubPtr);
      this.bootstrapExports.dealloc(schemaPtr);
    }
  }

  /** Grant trust — delegates to bootstrap.wasm. */
  trustGrant(
    algoId: number,
    publicKey: Uint8Array,
    schemaId: Uint8Array,
    granter?: { algoId: number; publicKey: Uint8Array }
  ): boolean {
    const pubPtr    = this.writeToBootstrap(publicKey);
    const schemaPtr = this.writeToBootstrap(schemaId);
    let granterPubPtr = 0;
    try {
      if (granter) {
        granterPubPtr = this.writeToBootstrap(granter.publicKey);
        return this.bootstrapExports.trust_grant(
          algoId, pubPtr, publicKey.length, schemaPtr, schemaId.length,
          granter.algoId, granterPubPtr, granter.publicKey.length
        ) === 1;
      }
      return this.bootstrapExports.trust_grant(
        algoId, pubPtr, publicKey.length, schemaPtr, schemaId.length,
        -1, 0, 0
      ) === 1;
    } finally {
      this.bootstrapExports.dealloc(pubPtr);
      this.bootstrapExports.dealloc(schemaPtr);
      if (granterPubPtr) this.bootstrapExports.dealloc(granterPubPtr);
    }
  }

  /** Revoke trust — delegates to bootstrap.wasm (cascades internally). */
  trustRevoke(algoId: number, publicKey: Uint8Array, schemaId: Uint8Array): void {
    const pubPtr    = this.writeToBootstrap(publicKey);
    const schemaPtr = this.writeToBootstrap(schemaId);
    try { this.bootstrapExports.trust_revoke(algoId, pubPtr, publicKey.length, schemaPtr, schemaId.length); }
    finally { this.bootstrapExports.dealloc(pubPtr); this.bootstrapExports.dealloc(schemaPtr); }
  }

  /** Derive a bootstrap schema_id: SHA-3-256(name). Use this for bootstrap
   *  schemas only (signature, trust.grant, …); app handlers must use
   *  deriveScopedId so the id incorporates the installer pubkey (README §5).
   *  Computed host-side directly via the genesis suite hash — there is no
   *  security boundary that requires the hash to live in bootstrap.wasm,
   *  and the round-trip cost (4 boundary crossings to compute one digest)
   *  was pure overhead. */
  deriveId(name: string): Uint8Array {
    return this.sodium.crypto_hash_sha3256(new TextEncoder().encode(name));
  }

  /** Genesis-suite hash (SHA-3-256) of arbitrary bytes. Used by the install
   *  handler to derive the wasm_hash passed to approveInstall, and available
   *  to deployers who want to compute the same hash off-line for allowlists. */
  genesisHash(bytes: Uint8Array): Uint8Array {
    return this.sodium.crypto_hash_sha3256(bytes);
  }

  /** Derive an installer-scoped schema_id: SHA-3-256(name || installer_pubkey).
   *  Required form for app handlers per README §5 — two different keys for
   *  the same canonical name produce different schema_ids, so installs cannot
   *  collide by accident. Consumers must know the installer's pubkey to reach
   *  the handler. */
  deriveScopedId(name: string, installerPubKey: Uint8Array): Uint8Array {
    const nameBytes = new TextEncoder().encode(name);
    const buf = new Uint8Array(nameBytes.length + installerPubKey.length);
    buf.set(nameBytes, 0);
    buf.set(installerPubKey, nameBytes.length);
    return this.sodium.crypto_hash_sha3256(buf);
  }

  /** Encode an envelope (README §2). Pure binary layout — no security boundary
   *  on the encoder side, so it lives in the host. The kernel still enforces
   *  the §2.2 64 KB limit on decode. */
  encodeEnvelope(version: number, schemaId: Uint8Array, payload: Uint8Array): Uint8Array {
    if (schemaId.length === 0 || schemaId.length > 255) throw new Error("encodeEnvelope: schema_id length must be 1..255");
    const total = 4 + schemaId.length + payload.length;
    if (total > MAX_ENVELOPE_BYTES) throw new Error("encodeEnvelope: envelope exceeds 64 KB");
    const out = new Uint8Array(total);
    out[0] = (MAGIC >> 8) & 0xff;
    out[1] = MAGIC & 0xff;
    out[2] = version;
    out[3] = schemaId.length;
    out.set(schemaId, 4);
    out.set(payload, 4 + schemaId.length);
    return out;
  }

  /** Build a trust.grant payload (README §7.2). Pure binary layout — the
   *  authorization gate is in handle_trust_grant, not here.
   *  Layout: seq u32 BE | action u8 | algo u16 | pubkey_len u16 | pubkey | schema_id_len u8 | schema_id
   *
   *  `seq` is the §4.4 replay-protection sequence number for the *signer*
   *  (the key that will wrap this payload, not the key being granted/revoked).
   *  Each signer's seq must strictly increase across every trust.grant
   *  message they produce; the handler tracks the high-water mark per
   *  (algoId, pubKey) and drops any payload with seq <= last_seen. */
  encodeGrant(seq: number, revoke: boolean, algoId: number, pubKey: Uint8Array, schemaId: Uint8Array): Uint8Array {
    if (pubKey.length === 0 || pubKey.length > 0xffff) throw new Error("encodeGrant: pubkey length must be 1..65535");
    if (schemaId.length === 0 || schemaId.length > 0xff) throw new Error("encodeGrant: schema_id length must be 1..255");
    if (seq < 0 || seq > 0xffffffff) throw new Error("encodeGrant: seq must fit in u32");
    const out = new Uint8Array(4 + 1 + 2 + 2 + pubKey.length + 1 + schemaId.length);
    let o = 0;
    writeU32BE(out, o, seq); o += 4;
    out[o++] = revoke ? 1 : 0;
    out[o++] = (algoId >> 8) & 0xff;
    out[o++] = algoId & 0xff;
    out[o++] = (pubKey.length >> 8) & 0xff;
    out[o++] = pubKey.length & 0xff;
    out.set(pubKey, o); o += pubKey.length;
    out[o++] = schemaId.length;
    out.set(schemaId, o);
    return out;
  }

  /** Sign + wrap an inner envelope in a signature envelope (README §6.3).
   *  Sender-side, genesis suite (Ed25519+SHA-3-256) only — pure host code,
   *  no bootstrap.wasm round-trip. Throws if the resulting envelope would
   *  exceed 65,536 bytes (§2.2) or if registerSignature has not been called. */
  wrap(privateKey: Uint8Array, publicKey: Uint8Array, innerBytes: Uint8Array): Uint8Array {
    if (!this._signatureId) throw new Error("wrap: registerSignature has not been called");
    // Genesis suite (Ed25519) requires exact key sizes. A short sk would cause
    // libsodium to read past the buffer and sign whatever happened to be there.
    if (privateKey.length !== GENESIS_SECRET_KEY_LEN) {
      throw new Error(`wrap: privateKey must be ${GENESIS_SECRET_KEY_LEN} bytes (Ed25519), got ${privateKey.length}`);
    }
    if (publicKey.length !== GENESIS_PUBKEY_LEN) {
      throw new Error(`wrap: publicKey must be ${GENESIS_PUBKEY_LEN} bytes (Ed25519), got ${publicKey.length}`);
    }
    const sig = this.sodium.crypto_sign_detached(innerBytes, privateKey);

    // §6.3 wrapper payload: algo u16 | signer_len u16 | signer | sig_len u16 | sig | inner
    const wrapperPayloadLen = 2 + 2 + GENESIS_PUBKEY_LEN + 2 + GENESIS_SIGNATURE_LEN + innerBytes.length;
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

    return this.encodeEnvelope(CURRENT_VERSION, this._signatureId, wrapperPayload);
  }

  /** Convenience: encode an inner envelope then wrap + sign it. */
  wrapAndEncode(
    privateKey: Uint8Array, publicKey: Uint8Array,
    version: number,
    schemaId: Uint8Array, payload: Uint8Array
  ): Uint8Array {
    const innerBytes = this.encodeEnvelope(version, schemaId, payload);
    return this.wrap(privateKey, publicKey, innerBytes);
  }
}
