# quickjs — in-repo quickjs-ng (emscripten) engine for the node/WASM loader

The engine the node-side confined realms run on (`safe-js.ts`), compiled to
emscripten WASM from the same quickjs-ng v0.16.1 source the native loader
builds (`native/qjs/build-qjs.sh`). It replaces the `@jitl/quickjs-ng-*`
npm variants, which vendored quickjs-ng **0.12.1** — a different engine
version than the native loader, which is exactly the drift this artifact
removes.

## Layout

- **`csrc/interface.c`** — the `QTS_*` ABI shim, forked from
  quickjs-emscripten v0.32.0's `c/interface.c` and **ours now**: it carries
  the fix for the 0.16.1 `JS_NewArrayBuffer` signature
  (`free_func` → `max_len` + `realloc_func`, the `realloc(ptr, 0)` free
  convention). Keeping the shim in-repo is what makes the blob reproducible.
- **`csrc/0001-bellard-module-detection.patch`** — the bellard-style
  `QTS_DetectModule` heuristic the emscripten build appends to the amalgam
  (upstream quickjs-emscripten's own patch, vendored).
- **`templates/` + `exportedRuntimeMethods.json`** — emscripten glue inputs
  from quickjs-emscripten v0.32.0, vendored verbatim (their Makefile's
  `--pre-js` files and `EXPORTED_RUNTIME_METHODS` list).
- **`dist/`** — the built artifact, checked in so a clone runs without emsdk:
  - `emscripten-module.wasm` + `emscripten-module.mjs` — the engine and its
    MODULARIZE glue (ESM, `EXPORT_NAME=QuickJSRaw`). Built for
    `ENVIRONMENT=web,node`: the browser apps vendor this same `dist/` and load
    it off a static server, and one glue that picks its loader at runtime beats
    a second `.browser.mjs` to keep in sync.
  - `ffi.mjs` — the cwrap bindings, generated from `csrc/interface.c`
    (the vendored copy IS the ABI contract the build's export list is drawn
    from).
  - `variant.mjs` — the quickjs-emscripten "variant" object that wires
    `ffi.mjs` + the glue into `newQuickJSWASMModuleFromVariant`. Reached as the
    package export `seedkernel-wasm/quickjs`, which is the specifier
    `safe-js.ts` names on every target.

## Rebuilding

Requires the Emscripten SDK (5.0.1) — `emcc` on PATH (e.g. `source
~/emsdk/emsdk_env.sh`), plus curl, unzip, patch, node:

    cd WASM/quickjs
    ./build-quickjs-ng.sh

The script fetches the quickjs-ng **v0.16.1** release amalgam (the same pin
`native/qjs/build-qjs.sh` compiles from), applies the patch, and installs
over `dist/`. After a rebuild, re-run the suites:

    cd .. && npm run build:host && npm test
    # and the seedstore mount repro: node repro-mount.mjs small-big

## Why not the npm variants

The published `@jitl/quickjs-ng-*` packages top out at 0.32.0, which vendors
quickjs-ng 0.12.1; nothing on npm ships 0.16.1. The native loader already
built its own 0.16.1 blob (`native/qjs/`), so the node side is the
odd-one-out only because its engine came from npm. This artifact is that
same owning-the-blob pattern applied to the emscripten build.

What stays from npm is `quickjs-emscripten-core`, the JS API layer over the
`QTS_*` ABI (`csrc/interface.c` is that ABI's other half, forked from the same
release). The `quickjs-emscripten` umbrella is deliberately **not** a
dependency: its added value is bundling default variants, which it does with
static imports of four Bellard-flavoured engines this realm never runs.
