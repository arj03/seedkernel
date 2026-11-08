#!/usr/bin/env bash
# Builds quic.wasm (quic.c over ngtcp2 and Monocypher) into $1: wasi-sdk's clang, then
# wasm-merge adding scratch.wat's `scratchSize`. Nothing in it reaches WASI, so the module
# imports nothing (§4.2). Run by scripts/build-quic.mjs, through WSL on Windows.
#
# Inputs:
#   quic.c       the module: the ABI, the paths, the keys.
#   scratch.wat  the `scratchSize` export.
#   ngtcp2       the QUIC library, fetched at the pin below, without its TLS helpers.
#   Monocypher   ChaCha20-Poly1305 and BLAKE2b, fetched at the pin below.
#
# Requires wasi-sdk (WASI_SDK, default /opt/wasi-sdk), binaryen (wasm-as, wasm-merge,
# wasm-opt), cmake and git.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$1"
work="$here/.build"
wasi_sdk="${WASI_SDK:-/opt/wasi-sdk}"

# Changing either is a new bundle: re-run net-udp.test.mjs.
ngtcp2_repo="https://github.com/ngtcp2/ngtcp2"
ngtcp2_pin="6a22a4d7a111f6b52391910e40ad3681a09cfb9c" # v1.26.0
monocypher_repo="https://github.com/LoupVaillant/Monocypher"
monocypher_pin="0d85f98c9d9b0227e42cf795cb527dff372b40a4" # 4.0.2

[ -d "$wasi_sdk" ] || { echo "no wasi-sdk at $wasi_sdk (set WASI_SDK)" >&2; exit 1; }
command -v wasm-merge >/dev/null || { echo "wasm-merge not found (install binaryen)" >&2; exit 1; }

fetch() {
  local dir="$work/$1"
  if [ ! -d "$dir/.git" ]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "$2"
  fi
  git -C "$dir" fetch -q --depth 1 origin "$3"
  git -C "$dir" checkout -q -f FETCH_HEAD
}
mkdir -p "$work"
fetch ngtcp2 "$ngtcp2_repo" "$ngtcp2_pin"
fetch monocypher "$monocypher_repo" "$monocypher_pin"

cmake -S "$work/ngtcp2" -B "$work/ngtcp2-build" \
  -DENABLE_LIB_ONLY=ON -DENABLE_SHARED_LIB=OFF -DENABLE_STATIC_LIB=ON -DBUILD_TESTING=OFF \
  -DENABLE_OPENSSL=OFF -DENABLE_GNUTLS=OFF -DENABLE_BORINGSSL=OFF -DENABLE_PICOTLS=OFF -DENABLE_WOLFSSL=OFF \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-O2 -ffunction-sections -fdata-sections" \
  -DCMAKE_TOOLCHAIN_FILE="$wasi_sdk/share/cmake/wasi-sdk-p1.cmake" -DWASI_SDK_PREFIX="$wasi_sdk" >/dev/null
cmake --build "$work/ngtcp2-build" -j"$(nproc)" >/dev/null

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# No start files: nothing runs at instantiation, and the only export is the ABI's (§4.1).
"$wasi_sdk/bin/clang" --target=wasm32-wasip1 -O2 -DNDEBUG -std=c11 -Wall -Wextra -Werror -Wno-unused-parameter \
  -ffunction-sections -fdata-sections \
  -I"$work/ngtcp2/lib/includes" -I"$work/ngtcp2-build/lib/includes" -I"$work/monocypher/src" \
  "$here/quic.c" "$work/monocypher/src/monocypher.c" "$work/ngtcp2-build/lib/libngtcp2.a" \
  -nostartfiles -Wl,--no-entry -Wl,--gc-sections -Wl,--strip-all -Wl,--export=scratch \
  -Wl,--max-memory=50331648 -o "$tmp/quic.wasm"
wasm-as "$here/scratch.wat" -o "$tmp/scratch.wasm"
wasm-merge "$tmp/quic.wasm" quic "$tmp/scratch.wasm" scratch \
  --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals \
  -o "$tmp/merged.wasm"
wasm-opt "$tmp/merged.wasm" -O2 --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  --enable-mutable-globals --strip-debug --strip-producers -o "$out"
