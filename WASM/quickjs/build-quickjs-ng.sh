#!/usr/bin/env bash
# Rebuilds dist/emscripten-module.{wasm,mjs} — the emscripten quickjs-ng 0.16.1
# engine the node/WASM loader runs its confined realms on (safe-js.ts).
#
# ONE glue for both targets (`ENVIRONMENT=web,node`): the browser apps vendor
# this same dist/ and load it from a static server, so a node-only glue —
# which reads the .wasm through `require("node:fs")` at module scope — would
# make safe-js.js unimportable in a browser. Emscripten guards each
# environment's loader behind a runtime `ENVIRONMENT_IS_*` test, so the browser
# never evaluates the `node:` imports and fetches the .wasm beside this module
# instead. A separate .browser.mjs (what the @jitl packages ship) would be a
# second glue over the same engine, i.e. a second thing to keep in sync.
#
# The blob is ours: csrc/ carries the QTS_* shim (forked from
# quickjs-emscripten v0.32.0's c/interface.c — the same ABI the npm @jitl
# variants use, so the JS API layer is the unchanged quickjs-emscripten-core
# package), and this script is that binary's source's other half.
#
# What it builds, and from where:
#   csrc/interface.c            — the QTS_* ABI shim (see README.md).
#   csrc/0001-*.patch           — the bellard-style module detection helper
#                                 (QTS_DetectModule) applied to the amalgam.
#   quickjs-ng                  — the engine, fetched at the pin below as the
#                                 release amalgam (quickjs-amalgam.zip).
#   templates/ + exportedRuntimeMethods.json
#                               — emscripten glue templates, from
#                                 quickjs-emscripten v0.32.0 (their Makefile's
#                                 inputs, vendored verbatim).
#
# Requires emsdk (5.0.1) with emcc on PATH, curl, unzip, patch, node (any).
#   ./build-quickjs-ng.sh       # build into .build/ and install over dist/
#
# After a build, re-run the WASM suite: cd WASM && npm test, plus the
# seedstore mount repro (node repro-mount.mjs small-big).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$here/.build"
dist="$here/dist"
version="v0.16.1"

# quickjs-ng v0.16.1 — the SAME pin the native loader builds
# (native/qjs/build-qjs.sh). Moving this is a deliberate engine upgrade:
# re-run the WASM and native suites, which drive every export the shim uses.
quickjs_pin="954dc53628e36891f93c359aa60895c2ae3dac6b"

command -v emcc >/dev/null || { echo "no emcc on PATH (source emsdk_env.sh)" >&2; exit 1; }
command -v unzip >/dev/null || { echo "unzip not found" >&2; exit 1; }
command -v patch >/dev/null || { echo "patch not found" >&2; exit 1; }
command -v node >/dev/null || { echo "node not found" >&2; exit 1; }

mkdir -p "$work" "$dist"

# Fetch the engine as the release amalgam (single-file C, same source the
# native build compiles from the git pin).
if [ ! -f "$work/quickjs-amalgam.c" ]; then
  echo "fetching quickjs-ng $version ($quickjs_pin) amalgam..."
  curl -fsSL -o "$work/quickjs-amalgam.zip" \
    "https://github.com/quickjs-ng/quickjs/releases/download/${version}/quickjs-amalgam.zip"
  unzip -q -o "$work/quickjs-amalgam.zip" -d "$work"
  # The zip may nest under quickjs-amalgam/ or quickjs/.
  if [ -d "$work/quickjs-amalgam" ]; then
    mv "$work/quickjs-amalgam"/*.c "$work/quickjs-amalgam"/*.h "$work/" 2>/dev/null || true
    rm -rf "$work/quickjs-amalgam"
  elif [ -d "$work/quickjs" ]; then
    mv "$work/quickjs"/*.c "$work/quickjs"/*.h "$work/" 2>/dev/null || true
    rm -rf "$work/quickjs"
  fi
fi

[ -f "$work/quickjs-amalgam.c" ] || { echo "no quickjs-amalgam.c after fetch" >&2; exit 1; }
# interface.c includes the amalgam headers by bare name; make them resolvable.
cp "$work/quickjs-libc.h" "$work/quickjs.h" "$work/" 2>/dev/null || true
[ -f "$work/quickjs.h" ] || { echo "no quickjs.h after fetch" >&2; exit 1; }

# Apply the shim's patches to the amalgam (idempotent).
patch -d "$work" -p1 -s -N < "$here/csrc/0001-bellard-module-detection.patch" 2>/dev/null || true
grep -q QTS_DetectModule "$work/quickjs-amalgam.c" \
  || { echo "module-detection patch did not apply" >&2; exit 1; }

# The exported-function list: what dist/ffi.mjs binds (the vendored ffi IS the
# ABI contract — it is generated from csrc/interface.c). _malloc/_free are the
# emscripten runtime methods the glue uses.
grep -oE 'cwrap\("QTS_[A-Za-z0-9_]+' "$dist/ffi.mjs" \
  | sed 's/cwrap("//' | sort -u \
  | awk 'BEGIN { printf "[\"_malloc\",\"_free\"" } { printf ",\"_%s\"", $0 } END { print "]" }' \
  > "$work/symbols.json"

echo "building with $(emcc --version | head -1)..."

emcc \
  -DQTS_USE_QUICKJS_NG -D_GNU_SOURCE -DQJS_BUILD_LIBC \
  -DCONFIG_VERSION=\"$version\" \
  -I"$work" \
  -Wcast-function-type \
  -s MODULARIZE=1 -s IMPORTED_MEMORY=1 -s EXPORT_NAME=QuickJSRaw \
  -s INVOKE_RUN=0 -s ALLOW_MEMORY_GROWTH=1 -s ALLOW_TABLE_GROWTH=1 \
  -s STACK_SIZE=5MB -s SUPPORT_ERRNO=0 -s IGNORE_MISSING_MAIN=0 --no-entry \
  -s AUTO_JS_LIBRARIES=0 -s -lccall.js -s AUTO_NATIVE_LIBRARIES=0 \
  -s AUTO_ARCHIVE_INDEXES=0 -s DEFAULT_TO_CXX=0 -s ALLOW_UNIMPLEMENTED_SYSCALLS=0 \
  -s MIN_NODE_VERSION=160000 -s NODEJS_CATCH_EXIT=0 -s EXPORT_ES6=1 \
  -s EXPORTED_RUNTIME_METHODS=@"$here/exportedRuntimeMethods.json" \
  -Oz -flto --closure 1 -s FILESYSTEM=0 \
  --pre-js "$here/templates/pre-extension.js" --pre-js "$here/templates/pre-wasmMemory.js" \
  -s ENVIRONMENT=web,node \
  -s EXPORTED_FUNCTIONS=@"$work/symbols.json" \
  -o "$dist/emscripten-module.mjs" \
  "$here/csrc/interface.c" "$work/quickjs-amalgam.c"

echo "wrote $(stat -c%s "$dist/emscripten-module.wasm") bytes -> $dist/emscripten-module.wasm"
echo "now run: cd .. && npm run build:host && npm test (and the seedstore mount repro)"
