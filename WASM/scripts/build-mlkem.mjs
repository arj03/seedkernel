// Builds browser/mlkem768.wasm — ML-KEM-768 (FIPS 203) for the primitive catalog
// (`ml-kem-768/*`, README §14.1) — from the pinned mlkem-native submodule in
// pq/mlkem-native. The sibling of build-mldsa.mjs, and everything that file's
// header says applies here.
//
// ONE artifact for all three targets: the browser instantiates it with
// WebAssembly, Node instantiates it with WebAssembly, and the Go loader
// instantiates it with wazero (native/mlkem.go, fed by copy-loader-wasm.mjs).
// The reason differs from ML-DSA's, though, and is worth stating: a KEM is not a
// verifier, so its accept/reject boundary is not consensus. What makes it one
// artifact is that a catalog entry is a *name* two nodes hand each other bytes
// under (§12.6) — two implementations that disagree on a rejected encoding do not
// disagree about a bundle, they simply fail to share a key, and the cheapest way
// not to find that out in production is not to have two implementations.
//
// The module has NO imports. Randomness is an argument (kem-shim.c, and the
// catalog is purely functional), memcpy/memset are compiled in, and there is no
// libc: a freestanding wasm32 build needs no WASI, no emscripten, and no
// per-target glue for a host to satisfy differently from another host.
//
// Requires clang (>= 15, any build with the wasm32 target). Run
// `git submodule update --init` first.

import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const pq = resolve(root, "pq");
const src = resolve(pq, "mlkem-native");
const out = resolve(root, "browser/mlkem768.wasm");

if (!existsSync(resolve(src, "mlkem/mlkem_native.c"))) {
  throw new Error("pq/mlkem-native is empty — run `git submodule update --init --recursive`");
}

const cc = process.env.CC ?? "clang";
const args = [
  "--target=wasm32",
  "-Os",
  "-std=c99",
  "-Wall",
  "-Wextra",
  "-Werror",
  // Freestanding: no libc is linked. The only stdlib headers reached are the ones
  // clang ships itself (stdint.h, stddef.h); mlkem-native's memcpy/memset/zeroize
  // are redirected to local definitions by pq/kem-config.h.
  "-nostdlib",
  "-ffreestanding",
  "-DNDEBUG",
  `-DMLK_CONFIG_FILE="${resolve(pq, "kem-config.h")}"`,
  // pq/include first: a two-declaration <string.h> so the build needs no sysroot.
  `-I${resolve(pq, "include")}`,
  `-I${resolve(src, "mlkem")}`,
  `-I${src}`,
  "-Wl,--no-entry",
  "-Wl,--export-dynamic",
  "-Wl,--export=__heap_base",
  "-Wl,--strip-all",
  // Keygen and encaps hold several polynomial vectors on the stack at once;
  // wasm-ld's 64 KB default is not enough and overflows silently into a trap.
  // 256 KB matches the ML-DSA build and leaves headroom.
  "-Wl,-z,stack-size=262144",
  "-Wl,--initial-memory=1048576",
  "-o",
  out,
  resolve(src, "mlkem/mlkem_native.c"),
  resolve(pq, "kem-shim.c"),
];

execFileSync(cc, args, { stdio: "inherit" });
console.log(`wrote ${statSync(out).size} bytes -> browser/mlkem768.wasm`);
