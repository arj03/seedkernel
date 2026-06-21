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

- **`qjs.wasm`** — the prebuilt engine: quickjs-ng wrapped by a small C shim that
  exposes the flat `QJS_*` C ABI with NaN-boxed JSValues (so every export
  takes/returns a single `i64`). Copied verbatim from
  `github.com/fastschema/qjs@v0.0.6` (MIT). ~1 MiB; embedded via `//go:embed` and
  driven over wazero — the Go build never compiles C.

To rebuild the blob, go to the upstream tag: it builds the shim against quickjs-ng
(a git submodule there) with wasi-sdk. We vendor only the finished `qjs.wasm`, not
the C sources — the `QJS_*` surface the Go bridge depends on is documented below.

Upstream: https://github.com/fastschema/qjs (MIT) · https://github.com/quickjs-ng/quickjs (MIT)

## ABI notes

- JSValue is a `uint64` (NaN boxing). A `*Value` wraps that handle.
- The only host import is `env.jsFunctionProxy`; the C trampoline packs its `argv`
  as `[fnID, ctxID, isAsync, promise, ...realArgs]`. Because quickjs `JS_TAG_INT == 0`,
  a small int's NaN-boxed word equals the integer, so the callback id round-trips as
  a plain `uint64`.
- "Packed pointer" returns (`QJS_ToCString`, `QJS_GetArrayBuffer`) point at an
  8-byte cell holding `(addr<<32 | size)`.

## Scope

Synchronous only — the bridge exports no Promises/async/`js_std_await`; every `QJS_*`
call is a plain synchronous Go→wasm call. The loader builds everything async *on top*
of this surface — a Go-owned event loop, timers, and blocking net — in `../loop.go`.
A separate `Runtime` is created per realm: a trusted host realm (`host.js` + the
sodium/fs/net shims + the shared net/cap-bridge JS) and a zero-authority confined
guest realm whose only seam is `host.call`. The wasm links quickjs-libc (WASI);
confinement hardening of that surface is future work.
