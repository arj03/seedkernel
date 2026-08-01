// Builds browser/mldsa65.wasm — the ML-DSA-65 verifier for manifest suite 0x02
// (§12.4, §14.1) — from the pinned mldsa-native submodule in pq/mldsa-native.
//
// ONE artifact for all three targets. The browser instantiates it with
// WebAssembly, Node instantiates it with WebAssembly, and the Go loader
// instantiates it with wazero (native/mldsa.go, fed by copy-loader-wasm.mjs) — the
// same bytes, so the accept/reject boundary cannot drift between a node that admits
// a bundle and a node that refuses it. That is the same reason Ed25519 stays on the
// shared libsodium.wasm rather than each target's native implementation.
//
// The module has NO imports. Randomness is an argument (shim.c), the FIPS 204
// context is an argument, memcpy/memset are compiled in, and there is no libc: a
// freestanding wasm32 build needs no WASI, no emscripten, and no per-target glue
// for a host to satisfy differently from another host.
//
// Requires clang (>= 15, any build with the wasm32 target — `apt install clang lld`
// suffices; no sysroot, no emsdk). Run `git submodule update --init` first.

import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const pq = resolve(root, "pq");
const src = resolve(pq, "mldsa-native");
const out = resolve(root, "browser/mldsa65.wasm");

if (!existsSync(resolve(src, "mldsa/mldsa_native.c"))) {
  throw new Error("pq/mldsa-native is empty — run `git submodule update --init --recursive`");
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
  // clang ships itself (stdint.h, stddef.h); mldsa-native's memcpy/memset/zeroize
  // are redirected to local definitions by pq/config.h.
  "-nostdlib",
  "-ffreestanding",
  "-DNDEBUG",
  `-DMLD_CONFIG_FILE="${resolve(pq, "config.h")}"`,
  // pq/include first: a two-declaration <string.h> so the build needs no sysroot.
  `-I${resolve(pq, "include")}`,
  `-I${resolve(src, "mldsa")}`,
  `-I${src}`,
  "-Wl,--no-entry",
  "-Wl,--export-dynamic",
  "-Wl,--export=__heap_base",
  "-Wl,--strip-all",
  // ML-DSA-65 signing needs ~75 KB of stack (MLD_TOTAL_ALLOC_65_* in
  // mldsa_native.h); wasm-ld's 64 KB default overflows it silently into a trap.
  // 256 KB leaves headroom without making the initial memory large.
  "-Wl,-z,stack-size=262144",
  "-Wl,--initial-memory=1048576",
  "-o",
  out,
  resolve(src, "mldsa/mldsa_native.c"),
  resolve(pq, "shim.c"),
];

execFileSync(cc, args, { stdio: "inherit" });
console.log(`wrote ${statSync(out).size} bytes -> browser/mldsa65.wasm`);
