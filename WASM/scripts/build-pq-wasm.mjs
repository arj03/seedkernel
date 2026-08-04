// build-pq-wasm.mjs — the shared half of build-mlkem.mjs / build-mldsa.mjs. Both
// PQ artifacts are the same shape of build: one C source from a pinned submodule
// in pq/, a config header redirecting memcpy/memset/zeroize (and any libc the PQ
// library expects) to local definitions, and a shim, compiled freestanding to
// wasm32 with the same flag set. The only things that differ are those four paths
// and the output name, so the flag list lives once here.
//
// The module has NO imports. Randomness is an argument (the shim), any context is
// an argument, memcpy/memset are compiled in, and there is no libc: a freestanding
// wasm32 build needs no WASI, no emscripten, and no per-target glue for a host to
// satisfy differently from another host.
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

/** @param {object} cfg
 *  @param {string} cfg.submodule   pq/<name> submodule dir (e.g. "mlkem-native")
 *  @param {string} cfg.marker      a file inside the submodule whose absence means
 *                                  the submodule was never checked out
 *  @param {string} cfg.cSource     the submodule-relative C source to compile
 *  @param {string} cfg.incDir      the submodule-relative include dir
 *  @param {string} cfg.configDefine the -D name pointing at the pq/ config header
 *  @param {string} cfg.configHeader  pq/<file> — the memcpy/memset/zeroize config
 *  @param {string} cfg.shim        pq/<file> — the exported-API shim
 *  @param {string} cfg.out         browser/<file>.wasm output */
export function buildPqWasm(cfg) {
  const src = resolve(pq, cfg.submodule);
  const out = resolve(root, cfg.out);

  if (!existsSync(resolve(src, cfg.marker))) {
    throw new Error(`pq/${cfg.submodule} is empty — run \`git submodule update --init --recursive\``);
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
    // clang ships itself (stdint.h, stddef.h); each PQ library's
    // memcpy/memset/zeroize are redirected to local definitions by its config header.
    "-nostdlib",
    "-ffreestanding",
    "-DNDEBUG",
    `-D${cfg.configDefine}="${resolve(pq, cfg.configHeader)}"`,
    // pq/include first: a two-declaration <string.h> so the build needs no sysroot.
    `-I${resolve(pq, "include")}`,
    `-I${resolve(src, cfg.incDir)}`,
    `-I${src}`,
    "-Wl,--no-entry",
    "-Wl,--export-dynamic",
    "-Wl,--export=__heap_base",
    "-Wl,--strip-all",
    // Keygen/encaps (ML-KEM) hold several polynomial vectors on the stack at once,
    // and ML-DSA-65 signing needs ~75 KB (MLD_TOTAL_ALLOC_65_*); wasm-ld's 64 KB
    // default overflows silently into a trap. 256 KB covers both with headroom.
    "-Wl,-z,stack-size=262144",
    "-Wl,--initial-memory=1048576",
    "-o",
    out,
    resolve(src, cfg.cSource),
    resolve(pq, cfg.shim),
  ];

  execFileSync(cc, args, { stdio: "inherit" });
  console.log(`wrote ${statSync(out).size} bytes -> ${cfg.out}`);
}
