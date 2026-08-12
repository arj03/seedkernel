#!/usr/bin/env bash
# Rebuilds qjs.wasm — the engine the confined realms run on (guest.go, main.go).
#
# The blob is no longer upstream's: csrc/ carries a shim we have changed (the execution
# deadline, see csrc/qjs.c), so a vendored binary nobody can reproduce would be a
# capability of this repo with no source. This script is that source's other half.
#
# What it builds, and from where:
#   csrc/            — the C shim exposing the flat QJS_* ABI the Go bridge drives.
#                      Ours: forked from fastschema/qjs v0.0.6 (MIT, LICENSE.fastschema).
#   quickjs-ng       — the engine, fetched at the pin below. Not vendored: it is ~2 MB of
#                      C we do not modify, and a pinned SHA says exactly as much as a copy.
#
# Requires wasi-sdk (the sysroot clang needs for a WASI target — the PQ builds are
# freestanding and need none, this one links libc), binaryen for wasm-opt, cmake, git.
#   Arch:   pacman -S binaryen cmake git   +   wasi-sdk in /opt
#   Debian: apt install binaryen cmake git +   wasi-sdk in /opt
#
#   ./build-qjs.sh          # build into .build/ and install over qjs.wasm
#   WASI_SDK=/path ./build-qjs.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$here/.build"
wasi_sdk="${WASI_SDK:-/opt/wasi-sdk}"

# quickjs-ng v0.16.1. Moving this is a deliberate engine upgrade: re-run the Go suite,
# which drives every export the bridge uses. The node/WASM loader's emscripten build
# (WASM/quickjs/build-quickjs-ng.sh) pins the SAME commit, so both engines stay one
# version.
quickjs_repo="https://github.com/quickjs-ng/quickjs"
quickjs_pin="954dc53628e36891f93c359aa60895c2ae3dac6b"

[ -d "$wasi_sdk" ] || { echo "no wasi-sdk at $wasi_sdk (set WASI_SDK)" >&2; exit 1; }
command -v wasm-opt >/dev/null || { echo "wasm-opt not found (install binaryen)" >&2; exit 1; }

mkdir -p "$work"
if [ ! -d "$work/quickjs/.git" ]; then
  git init -q "$work/quickjs"
  git -C "$work/quickjs" remote add origin "$quickjs_repo" 2>/dev/null || true
fi
git -C "$work/quickjs" fetch -q --depth 1 origin "$quickjs_pin"
git -C "$work/quickjs" checkout -q FETCH_HEAD

# The shim is compiled from csrc/ rather than copied into the engine tree: the cmake
# include below names it by absolute path, so the engine checkout stays pristine and
# `git -C .build/quickjs status` is a real answer about the engine.
cmake -S "$work/quickjs" -B "$work/build" \
  -DQJS_BUILD_LIBC=ON \
  -DQJS_BUILD_CLI_WITH_MIMALLOC=OFF \
  -DCMAKE_TOOLCHAIN_FILE="$wasi_sdk/share/cmake/wasi-sdk.cmake" \
  -DCMAKE_PROJECT_INCLUDE="$here/csrc/qjswasm.cmake" >/dev/null

make -C "$work/build" qjswasm -j"$(nproc)"

# -O3 after the link, as upstream's Makefile does. It buys little over LTO here, but it
# is part of the recipe the vendored blob was built with and dropping it would make this
# script a different build rather than the same one.
wasm-opt -O3 "$work/build/qjswasm" -o "$here/qjs.wasm"
echo "wrote $(stat -c%s "$here/qjs.wasm") bytes -> $here/qjs.wasm"
echo "now run: cd .. && go test ./..."
