# qjs — in-repo QuickJS bridge

A thin Go↔wazero bridge to the **quickjs-ng** engine, replacing
`github.com/fastschema/qjs`. That module pinned an old wazero and carried a
reflection/generics marshaling layer the loader doesn't need — it only needs a
small, synchronous slice of the API (objects, strings, ArrayBuffers, function
callbacks, eval, invoke). This package implements exactly that over the same
prebuilt wasm and lets us own the wazero version.

This is **not** a binary-size win: the stripped loader is ~7.5 MiB either way,
dominated by **wazero's compiler backend** (~4 MiB, linked regardless), with the Go
runtime (~2.4 MiB) and the qjs+libsodium wasm blobs (~1.3 MiB) making up the rest —
the fastschema marshaling layer was never the cost. The motivation is owning the
wazero version and shedding unused complexity, not MiB.

## Vendored asset

- **`csrc/`** — the C shim that exposes the flat `QJS_*` ABI with NaN-boxed JSValues
  (so every export takes/returns a single `i64`). Forked from
  `github.com/fastschema/qjs@v0.0.6` (MIT, `csrc/LICENSE.fastschema`) and **ours now**:
  it carries the execution deadline the guest realm's budget is built on
  (`QJS_SetDeadline` / `QJS_TakeInterrupted`, `csrc/qjs.c`), which upstream ships
  commented out — its `New_QJS` accepts a `max_execution_time` and ignores it.
- **`qjs.wasm`** — that shim linked against quickjs-ng, checked in (~1.3 MiB) and
  embedded via `//go:embed`, so a clone builds the loader with nothing but Go.

`./build-qjs.sh` rebuilds it: fetches quickjs-ng at the commit pinned in the script,
compiles `csrc/` against it with wasi-sdk, and installs the result over `qjs.wasm`.
The engine is fetched rather than vendored — it is ~2 MB of C we do not modify, and a
pinned SHA says as much as a copy. Rebuilding is not part of the Go build, and a
change to `csrc/` is not live until you run it; `go test ./...` from `native/` drives
every export the bridge uses and is the check that it worked.

Upstream: https://github.com/fastschema/qjs (MIT) · https://github.com/quickjs-ng/quickjs (MIT)

## ABI notes

- JSValue is a `uint64` (NaN boxing). A `*Value` wraps that handle.
- The only host import is `env.jsFunctionProxy`; the C trampoline packs its `argv`
  as `[fnID, ctxID, isAsync, promise, ...realArgs]`. Because quickjs `JS_TAG_INT == 0`,
  a small int's NaN-boxed word equals the integer, so the callback id round-trips as
  a plain `uint64`.
- "Packed pointer" returns (`QJS_ToCString`, `QJS_GetArrayBuffer`) point at an
  8-byte cell holding `(addr<<32 | size)`.
- `QJS_SetDeadline(ns)` arms the interrupt handler for `ns` from now, `0` disarms; the
  module resolves it against its own monotonic clock, so the host passes a duration and
  never has to share a clock origin. `QJS_TakeInterrupted()` reports whether the
  deadline has fired since it was last asked, and clears the flag — the only way to
  know, since an interrupt that lands in a promise-reaction job has its exception
  consumed by the job loop rather than returned to whoever pumped it.

## Scope

Synchronous only — the bridge exports no Promises/async/`js_std_await`; every `QJS_*`
call is a plain synchronous Go→wasm call. The loader builds everything async *on top*
of this surface — a Go-owned event loop, timers, and blocking net — in `../loop.go`.
A separate `Runtime` is created per realm: a trusted host realm (the sodium/fs/net
shims + the shared installer/net/guest-seam JS) and a zero-authority confined
guest realm whose only seam is `host.call`. The wasm links quickjs-libc (WASI);
confinement hardening of that surface is future work.
