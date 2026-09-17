#!/usr/bin/env bash
# Rebuilds qjs.wasm — the engine every realm runs on (main.go, guest.go).
#
# What it builds, and from where:
#   csrc/shim.c      — the flat QJS_* ABI the Go bridge drives (qjs.go, value.go).
#   csrc/*.patch     — applied to the engine before the build (see each patch's hunks).
#   quickjs-ng       — the engine, fetched at the pin below. Not vendored: it is ~2 MB of
#                      C, and a pinned SHA plus the patches say exactly as much as a copy.
#
# The build links the engine and wasi-libc, and nothing of quickjs-libc.
#
# Requires wasi-sdk (the sysroot clang needs for a WASI target — the PQ builds are
# freestanding and need none, this one links libc), binaryen for wasm-opt, cmake, git.
#   Arch:   pacman -S binaryen cmake git   +   wasi-sdk in /opt
#   Debian: apt install binaryen cmake git +   wasi-sdk in /opt
#
#   ./build-qjs.sh          # build into .build/ and install over qjs.wasm
#   WASI_SDK=/path ./build-qjs.sh
set -euo pipefail
shopt -s nullglob # no patches is a patch set too

here="$(cd "$(dirname "$0")" && pwd)"
work="$here/.build"
wasi_sdk="${WASI_SDK:-/opt/wasi-sdk}"

# quickjs-ng v0.16.2. Moving this is a deliberate engine upgrade: re-run the Go suite,
# which drives every export the bridge uses, and check the patches still apply. The
# node/WASM loader's emscripten build (WASM/quickjs/build-quickjs-ng.sh) pins the SAME
# commit, so both engines stay one version.
quickjs_repo="https://github.com/quickjs-ng/quickjs"
quickjs_pin="1ab8676f4b6d6d669baeb5f21790fb9734636a20"

[ -d "$wasi_sdk" ] || { echo "no wasi-sdk at $wasi_sdk (set WASI_SDK)" >&2; exit 1; }
command -v wasm-opt >/dev/null || { echo "wasm-opt not found (install binaryen)" >&2; exit 1; }

mkdir -p "$work"
if [ ! -d "$work/quickjs/.git" ]; then
  git init -q "$work/quickjs"
  git -C "$work/quickjs" remote add origin "$quickjs_repo" 2>/dev/null || true
fi
git -C "$work/quickjs" fetch -q --depth 1 origin "$quickjs_pin"
# Forced, so a previous run's patched files give way to the pin before patching again.
git -C "$work/quickjs" checkout -q -f FETCH_HEAD
for patch in "$here"/csrc/*.patch; do
  git -C "$work/quickjs" apply "$patch"
done

# The shim is compiled from csrc/ rather than copied into the engine tree: the cmake
# include below names it by absolute path, so `git -C .build/quickjs diff` shows exactly
# the patches and nothing else.
cmake -S "$work/quickjs" -B "$work/build" \
  -DQJS_BUILD_LIBC=OFF \
  -DQJS_BUILD_CLI_WITH_MIMALLOC=OFF \
  -DCMAKE_TOOLCHAIN_FILE="$wasi_sdk/share/cmake/wasi-sdk.cmake" \
  -DCMAKE_PROJECT_INCLUDE="$here/csrc/qjswasm.cmake" >/dev/null

make -C "$work/build" qjswasm -j"$(nproc)"

# A post-link pass over what LTO already optimized, for size.
wasm-opt -O3 "$work/build/qjswasm" -o "$here/qjs.wasm"
echo "wrote $(stat -c%s "$here/qjs.wasm") bytes -> $here/qjs.wasm"
echo "now run: cd .. && go test ./..."
