# qjs: in-repo QuickJS bridge

A thin Go↔wazero bridge to the **quickjs-ng** engine: objects, strings,
ArrayBuffers, function callbacks, eval, invoke and the job queue — the synchronous
slice of the API the native host uses, and nothing more.

## Files

- **`csrc/shim.c`** — the flat `QJS_*` ABI `qjs.go` and `value.go` drive, and the
  execution deadline the guest realm's budget is built on (`QJS_SetDeadline` /
  `QJS_TakeInterrupted`). The exports are an allowlist in `csrc/qjswasm.cmake`.
- **`csrc/*.patch`** — applied to the engine before the build.
  `0001-wasi-stack-limit.patch` keeps QuickJS's stack limit, which quickjs-ng
  switches off for WASI; without it, deep recursion runs off the wasm stack into a
  trap that leaves the engine unusable, instead of throwing a `RangeError`.
- **`qjs.wasm`** — the shim linked against the engine, checked in (~1.25 MiB) and
  embedded via `//go:embed`, so a clone builds the binary with nothing but Go.

`./build-qjs.sh` rebuilds it: fetches quickjs-ng at the commit pinned in the script,
applies the patches, compiles `csrc/` against it with wasi-sdk, and installs the
result over `qjs.wasm`. The engine is fetched rather than vendored — it is ~2 MB of
C, and a pinned SHA plus the patches say as much as a copy. Rebuilding is not part of
the Go build, and a change to `csrc/` is not live until you run it; `go test ./...`
from `native/` drives every export the bridge uses and is the check that it worked.

The JS platform's engine — `WASM/quickjs/` — is the emscripten build of the **same**
quickjs-ng commit, so both targets run one engine version; move the pin in both build
scripts together.

Upstream: https://github.com/quickjs-ng/quickjs (MIT)

## ABI

- A JSValue is one `uint64` (NaN boxing); a `*Value` wraps that handle.
- An export that answers an address and a length (`QJS_ToCString`, `QJS_GetBytes`)
  packs both into its `i64` as `(addr<<32 | len)`, so there is no result cell to free.
- The only host import is `env.callGo(ctx, this, argc, argv, id)`: a JS call to the Go
  function registered under `id`, which `QJS_NewFunction` stores on the engine function.
- `QJS_GetBytes` reads an ArrayBuffer's or a TypedArray's storage from the engine's own
  slots, never from properties: no JS runs, and an object that only looks like a view
  is refused.
- `QJS_Eval` answers the completion value as it stands — a promise is not awaited — and
  `QJS_RunJobs` drains the job queue. For a runtime created to track rejections,
  `QJS_RunJobs` also counts the promises still rejected with no handler once the queue
  is empty, and `QJS_TakeRejection` hands them over.
- `QJS_SetDeadline(ns)` arms the interrupt handler for `ns` from now, `0` disarms; the
  module resolves it against its own monotonic clock, so the host passes a duration and
  never has to share a clock origin. `QJS_TakeInterrupted()` reports whether the
  deadline has fired since it was last asked, and clears the flag — the only way to
  know, since an interrupt that lands in a promise-reaction job has its exception
  consumed by the job loop rather than returned to whoever pumped it.
- The module is a WASI reactor: `_initialize` runs once, at instantiation. Its shadow
  stack is 2 MiB, first in linear memory; the engine's own limit (its default, 1 MiB)
  throws well before the end of it.

## Scope

Synchronous only — every `QJS_*` call is a plain synchronous Go→wasm call, and the
native host builds everything async on top of it: a Go-owned event loop, timers and socket
delivery, in `../loop.go`. A separate `Runtime` is created per realm: the trusted host
realm (the platform primitives plus the shared shell JS) and each zero-authority guest
realm, whose only seam is `host.call`.

No realm reaches the host through the engine itself. The build links no quickjs-libc —
no std/os/bjson modules and none of their globals — and sets no module loader, so there
is nothing to import and no module name that resolves. The engine's WASI imports are
answered by `instantiateWASI` with stubs that refuse everything but `clock_time_get`,
which the engine's own clock reads. `wasi_test.go` pins that nothing reaches another
stub — but for wasi-libc's allocator setup, which asks for entropy once and settles for
a fixed value when refused — and `../guest_confinement_test.go` pins the missing
globals and modules.
