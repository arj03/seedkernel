// safe-js — a zero-authority JavaScript sandbox. It runs untrusted/confined JS
// inside a QuickJS interpreter compiled to WASM (quickjs-emscripten, the sync
// non-Asyncify build), driven from the host. A fresh QuickJS context has *only* the
// ECMAScript intrinsics, so the guest cannot even name `fs`/`net`/`Bun`/`process`/
// `fetch` — confinement is the default, not something we lock down (ShadowRealm was
// disqualified on exactly this; see the ShadowRealm probes). The single seam to the
// outside is one injected host function, `__host_call`, which funnels every capability
// access through a copy-model byte boundary, the same shape as the KernelHost handler
// bridges.
//
// Async seam: a guest is typically multi-step, and the net steps genuinely round-trip.
// `host.call` resolves a **sync op** (crypto/fs/clock/module) to its bytes immediately
// and a **net op** to a real Promise the guest `await`s — implemented with
// quickjs-emscripten's deferred promise (`ctx.newPromise()`): the host function returns
// the deferred's handle and settles it when the bridge promise resolves, pumping
// `executePendingJobs()` so the guest's awaiting continuation runs. There is no Asyncify
// and no host-driven step loop: a suspended async guest is just heap state, so the same
// realm can be re-entered synchronously to serve a request (`callSync`, the holder path)
// while an initiator (`call`) is parked mid-`await`. One `quickjs.wasm` build serves both
// roles. An app builds its own guest confinement on top of this generic primitive
// (README §12.3).

import {
  newQuickJSWASMModule,
  type QuickJSWASMModule,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten";
// Use the actively-maintained quickjs-ng build rather than quickjs-emscripten's default
// (original-Bellard) variant. Only the non-Asyncify (sync) flavour is needed now — net is
// a real Promise resolved by the host, not an Asyncify stack unwind.
//
// This variant package is CJS, so under `nodenext` TypeScript types its default export as
// the module namespace, whereas the runtime default import is the variant object itself
// (verified). Cast to the factory's own parameter type to bridge that interop gap.
import ngReleaseSyncMod from "@jitl/quickjs-ng-wasmfile-release-sync";
const ngReleaseSync = ngReleaseSyncMod as unknown as NonNullable<
  Parameters<typeof newQuickJSWASMModule>[0]
>;

/** The one capability seam. `op` selects a host capability (net / store / crypto / clock /
 *  rand, mapped by the host); `payload`/return are opaque bytes, exactly like
 *  `kernel.call(name, payload) -> bytes`. A sync op returns bytes directly; a net op — the
 *  only genuinely async one — returns a Promise the guest awaits. */
export type SafeRealmBridge = (op: number, payload: Uint8Array) => Promise<Uint8Array> | Uint8Array;

export interface SafeRealmOptions {
  /** Guest source. Runs in the sandbox; registers entrypoints via the injected
   *  `register(name, fn)` (see the preamble below). */
  source: string;
  /** The single host capability funnel. */
  bridge: SafeRealmBridge;
  /** Hard cap on the realm's heap (default 64 MiB). A runaway guest hits this
   *  instead of the host's memory. */
  memoryLimitBytes?: number;
  /** Optional wall-clock budget per `call()` (ms). Coarse: it counts time spent
   *  awaiting host bridges too, so size it generously. The fine-grained CPU
   *  watchdog stays a host Worker concern (README §4.3). */
  deadlineMs?: number;
}

export interface SafeRealm {
  /** Invoke a guest entrypoint as an *initiator* (may `await` net). The arg and result
   *  cross as raw bytes (the copy model). Resolves when the guest promise settles —
   *  including all awaited host bridges. Concurrent `call()`s on one realm are safe: the
   *  arg is consumed synchronously before the first `await`, so they never clobber. */
  call(entry: string, payload: Uint8Array): Promise<Uint8Array>;
  /** Invoke a guest entrypoint synchronously — the *holder* request side (README §12.8).
   *  The entrypoint runs straight through to its bytes without yielding, so it can run
   *  *while* an initiator `call()` is parked mid-`await` in the same realm (a suspended
   *  async function is heap state; this is an ordinary re-entrant JS call). The
   *  entrypoint must reach only sync ops — a net op returns a Promise a sync entrypoint
   *  cannot resolve, which surfaces as an error here by design. Never pumps the job
   *  queue, so a re-entrant holder call cannot advance a parked initiator's continuation
   *  out of order. */
  callSync(entry: string, payload: Uint8Array): Uint8Array;
  dispose(): void;
}

// The guest-side preamble. Defines the airtight ABI the guest is written against:
// `host.call(op, bytes)` over the single seam — bytes for a sync op, a Promise for a net
// op — and `register`/`__invoke` for entrypoint dispatch. Pure JS — no authority.
const PREAMBLE = `
globalThis.host = {
  // __host_call returns an ArrayBuffer for a sync op (crypto/fs/clock/module) and a
  // Promise<ArrayBuffer> for a net op (a genuine round trip). So a guest's
  // 'await host.call(...)' resolves net transparently, while a sync op is returned
  // directly (awaiting a plain value is a harmless no-op). Real promises mean a fan-out
  // is just 'await Promise.all(peers.map(p => host.call(CAP_NET_SEND, ...)))'.
  call(op, bytes) {
    const ab = bytes instanceof ArrayBuffer
      ? bytes
      : (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength)
        ? bytes.buffer
        : bytes.slice().buffer;
    const r = __host_call(op, ab);
    return r instanceof ArrayBuffer ? new Uint8Array(r) : r.then((b) => new Uint8Array(b));
  },
};
globalThis.__entries = Object.create(null);
globalThis.register = (name, fn) => { globalThis.__entries[name] = fn; };
function __norm(out) {
  if (out instanceof ArrayBuffer) return out;
  if (out instanceof Uint8Array) {
    return (out.byteOffset === 0 && out.byteLength === out.buffer.byteLength)
      ? out.buffer : out.slice().buffer;
  }
  throw new Error("safe-js: entrypoint must return Uint8Array | ArrayBuffer");
}
globalThis.__invoke = (name, argBuf) => {
  const fn = globalThis.__entries[name];
  if (typeof fn !== "function") throw new Error("safe-js: no entrypoint '" + name + "'");
  // A synchronous entrypoint (the holder 'handle') returns bytes directly; an async
  // entrypoint (an initiator 'put'/'get') returns a guest promise the host settles.
  // __norm normalizes both to an ArrayBuffer.
  const out = fn(new Uint8Array(argBuf));
  return out && typeof out.then === "function" ? out.then(__norm) : __norm(out);
};
`;

let modulePromise: Promise<QuickJSWASMModule> | undefined;
/** The QuickJS WASM module is loaded once and shared by all realms. */
function getModule(): Promise<QuickJSWASMModule> {
  return (modulePromise ??= newQuickJSWASMModule(ngReleaseSync));
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength
    ? (u8.buffer as ArrayBuffer)
    : (u8.slice().buffer as ArrayBuffer);
}

/** Heap cap + the optional per-call wall-clock deadline. Returns the hook each
 *  `call()` uses to re-arm the deadline. */
function configureRealm(ctx: QuickJSContext, opts: SafeRealmOptions): () => void {
  ctx.runtime.setMemoryLimit(opts.memoryLimitBytes ?? 64 * 1024 * 1024);
  let deadline = Infinity;
  if (opts.deadlineMs !== undefined) {
    ctx.runtime.setInterruptHandler(() => Date.now() > deadline);
  }
  return () => { if (opts.deadlineMs !== undefined) deadline = Date.now() + opts.deadlineMs; };
}

/** Stage the entrypoint argument as the realm global `__arg` (copy boundary). */
function stageArg(ctx: QuickJSContext, payload: Uint8Array): void {
  const argHandle = ctx.newArrayBuffer(toArrayBuffer(payload));
  ctx.setProp(ctx.global, "__arg", argHandle);
  argHandle.dispose();
}

/** Copy an op payload out of WASM memory (the buffer may move under us). */
function copyPayload(ctx: QuickJSContext, payloadHandle: QuickJSHandle): Uint8Array {
  const lt = ctx.getArrayBuffer(payloadHandle);
  const payload = lt.value.slice();
  lt.dispose();
  return payload;
}

/** Take ownership of a result handle and copy its bytes out (copy boundary). */
function takeBytes(ctx: QuickJSContext, handle: QuickJSHandle): Uint8Array {
  const lt = ctx.getArrayBuffer(handle);
  const out = lt.value.slice();
  lt.dispose();
  handle.dispose();
  return out;
}

const invokeSrc = (entry: string): string => `__invoke(${JSON.stringify(entry)}, __arg)`;

export async function createSafeRealm(opts: SafeRealmOptions): Promise<SafeRealm> {
  const mod = await getModule();
  const ctx: QuickJSContext = mod.newContext();
  const armDeadline = configureRealm(ctx, opts);
  let disposed = false;

  // The single seam. QuickJS calls it synchronously: a sync op resolves to its bytes and
  // we hand the ArrayBuffer straight back; a net op returns a Promise, so we create a
  // QuickJS deferred, settle it when the bridge promise resolves, and pump pending jobs
  // so the guest's awaiting continuation runs. Returning the deferred's handle from a
  // newFunction needs no other cleanup as long as resolve/reject fires (quickjs-emscripten
  // deferred-promise contract).
  const hostCall = ctx.newFunction("__host_call", (opHandle, payloadHandle) => {
    const op = ctx.getNumber(opHandle);
    const result = opts.bridge(op, copyPayload(ctx, payloadHandle));
    if (!result || typeof (result as Promise<Uint8Array>).then !== "function") {
      // Sync op — return the bytes directly (no promise, no job queue).
      return ctx.newArrayBuffer(toArrayBuffer(result as Uint8Array));
    }
    // Net op — a genuine round trip. Bridge it through a deferred promise.
    const deferred = ctx.newPromise();
    (result as Promise<Uint8Array>).then(
      (bytes) => {
        if (disposed || !ctx.alive) return;
        const ab = ctx.newArrayBuffer(toArrayBuffer(bytes));
        deferred.resolve(ab);       // borrows ab; does not dispose it, so we do
        ab.dispose();
        ctx.runtime.executePendingJobs();
      },
      (err) => {
        if (disposed || !ctx.alive) return;
        const e = ctx.newError(String((err && (err as Error).message) || err));
        deferred.reject(e);
        e.dispose();
        ctx.runtime.executePendingJobs();
      },
    );
    return deferred.handle;
  });
  ctx.setProp(ctx.global, "__host_call", hostCall);
  hostCall.dispose();

  // Load the ABI preamble, then the guest. Neither has authority. Each eval's completion
  // value (the trailing assignment) is an owned handle — dispose it so nothing leaks past
  // the context (the QuickJS build asserts on leaks).
  ctx.unwrapResult(ctx.evalCode(PREAMBLE, "safe-js-preamble.js")).dispose();
  ctx.unwrapResult(ctx.evalCode(opts.source, "safe-js-guest.js")).dispose();

  return {
    async call(entry: string, payload: Uint8Array): Promise<Uint8Array> {
      armDeadline();
      stageArg(ctx, payload);
      // evalCode runs the entrypoint synchronously up to its first await; the completion
      // value is either the bytes (sync entrypoint) or a pending guest promise (async
      // entrypoint). resolvePromise normalizes both to a native promise, but it settles
      // only once the job queue is pumped — hence resolvePromise → executePendingJobs →
      // await, in that order (awaiting before the first pump would stall a sync entrypoint).
      // Net awaits are then driven by each deferred's own executePendingJobs on settle.
      const evalResult = ctx.unwrapResult(ctx.evalCode(invokeSrc(entry), "safe-js-invoke.js"));
      const settledNative = ctx.resolvePromise(evalResult);
      ctx.runtime.executePendingJobs();
      const settled = await settledNative;
      evalResult.dispose();
      return takeBytes(ctx, ctx.unwrapResult(settled));
    },
    callSync(entry: string, payload: Uint8Array): Uint8Array {
      armDeadline();
      stageArg(ctx, payload);
      // A sync (holder) entrypoint returns its ArrayBuffer directly. Deliberately no
      // executePendingJobs: a re-entrant holder call must not advance a parked
      // initiator's continuation. If a net op slipped in, the result is a guest promise
      // and getArrayBuffer throws — by design (a holder answers from local fs + crypto).
      return takeBytes(ctx, ctx.unwrapResult(ctx.evalCode(invokeSrc(entry), "safe-js-invoke.js")));
    },
    dispose(): void {
      disposed = true;
      ctx.dispose();
    },
  };
}
