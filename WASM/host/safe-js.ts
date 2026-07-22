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
// `host.call` resolves a **sync op** (crypto/fs/clock/module) to its bytes immediately and
// a **net op** to a real Promise the guest `await`s. The guest builds that Promise itself
// (the shared preamble parks it under a `callId`); this host returns `null` to say "started
// async", then settles it with `__netResolve`/`__netReject` and pumps `executePendingJobs()`
// so the awaiting continuation runs. Deliberately NOT quickjs-emscripten's `newPromise()`
// deferred: keeping the async half in plain ECMAScript is what lets this host and the
// native loader (guest.go, quickjs-ng over wazero, which has no promise primitive) share
// ONE preamble — see `guestPreamble` in cap-bridge.ts.
//
// There is no Asyncify and no host-driven step loop: a suspended async guest is just heap
// state, so the same realm can be re-entered synchronously to serve a request (`callSync`,
// the holder path) while an initiator (`call`) is parked mid-`await`. One `quickjs.wasm`
// build serves both roles. An app builds its own guest confinement on top of this generic
// primitive (README §12.3).

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

// The guest-side ABI, shared with the native loader. See `guestPreamble` for the
// `__host_call` / `__netResolve` contract this file implements.
import { guestPreamble } from "./cap-bridge.js";

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

  // Settle a parked net op by calling the guest's own __netResolve/__netReject (the
  // preamble's half of the contract), then pump so the awaiting continuation runs.
  const settleNet = (fn: "__netResolve" | "__netReject", callId: number, arg: QuickJSHandle): void => {
    const settler = ctx.getProp(ctx.global, fn);
    const id = ctx.newNumber(callId);
    ctx.unwrapResult(ctx.callFunction(settler, ctx.undefined, id, arg)).dispose();
    id.dispose();
    arg.dispose();
    settler.dispose();
    ctx.runtime.executePendingJobs();
  };

  // The single seam. QuickJS calls it synchronously: a sync op resolves to its bytes and
  // we hand the ArrayBuffer straight back; a net op genuinely round-trips, so we return
  // null — the preamble parks a Promise under callId — and settle it when the bridge
  // promise resolves. Returning null (rather than a host-created deferred) is what keeps
  // this seam identical to the native loader's; see guestPreamble.
  const hostCall = ctx.newFunction("__host_call", (opHandle, callIdHandle, payloadHandle) => {
    const op = ctx.getNumber(opHandle);
    const callId = ctx.getNumber(callIdHandle);
    const result = opts.bridge(op, copyPayload(ctx, payloadHandle));
    if (!result || typeof (result as Promise<Uint8Array>).then !== "function") {
      // Sync op — return the bytes directly (no promise, no job queue).
      return ctx.newArrayBuffer(toArrayBuffer(result as Uint8Array));
    }
    // Net op — a genuine round trip. The guest holds the Promise; we settle it by callId.
    (result as Promise<Uint8Array>).then(
      (bytes) => {
        if (disposed || !ctx.alive) return;
        settleNet("__netResolve", callId, ctx.newArrayBuffer(toArrayBuffer(bytes)));
      },
      (err) => {
        if (disposed || !ctx.alive) return;
        settleNet("__netReject", callId, ctx.newString(String((err && (err as Error).message) || err)));
      },
    );
    return ctx.null;
  });
  ctx.setProp(ctx.global, "__host_call", hostCall);
  hostCall.dispose();

  // Load the ABI preamble, then the guest. Neither has authority. Each eval's completion
  // value (the trailing assignment) is an owned handle — dispose it so nothing leaks past
  // the context (the QuickJS build asserts on leaks).
  ctx.unwrapResult(ctx.evalCode(guestPreamble(), "guest-preamble.js")).dispose();
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
