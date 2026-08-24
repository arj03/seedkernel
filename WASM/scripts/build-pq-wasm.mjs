// Shared half of build-mlkem.mjs / build-mldsa.mjs: one C source from a pinned pq/
// submodule, a config header redirecting memcpy/memset/zeroize to local definitions, and
// a shim — only those paths and the output name differ, so the flag list lives once here.
//
// The wasm has NO imports: randomness and context are shim arguments, memcpy/memset are
// compiled in, no libc — so no WASI, no emscripten, no per-host glue.
//
// Requires clang with a wasm32 target (no sysroot/emsdk; `apt install clang lld`).
// On Windows the compiler lives in WSL (as native/gorun.sh expects the Go toolchain) —
// one artifact must be byte-identical everywhere (§12.4). Set CC to use a native compiler.
import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const pq = resolve(root, "pq");

/** `C:\dir\file` → `/mnt/c/dir/file`, anywhere inside an argument (paths can be
 *  prefixed like `-I<path>` or wrapped in quotes, so replacement is per-occurrence). */
const toWslPath = (arg) =>
  arg.replace(/([A-Za-z]):\\([^"]*)/g,
    (_, drive, rest) => `/mnt/${drive.toLowerCase()}/${rest.replace(/\\/g, "/")}`);

/** @param {object} cfg  build inputs: pq submodule + marker (presence = checked out),
 *  cSource/incDir, the config define/header (memcpy/memset/zeroize redirect), shim, out. */
export function buildPqWasm(cfg) {
  const src = resolve(pq, cfg.submodule);
  const out = resolve(root, cfg.out);

  if (!existsSync(resolve(src, cfg.marker))) {
    throw new Error(`pq/${cfg.submodule} is empty — run \`git submodule update --init --recursive\``);
  }

  const args = [
    "--target=wasm32",
    "-Os",
    "-std=c99",
    "-Wall",
    "-Wextra",
    "-Werror",
    // Freestanding: no libc is linked, and the only stdlib headers reached are the ones
    // clang ships itself. Each PQ library's memcpy/memset/zeroize are redirected to
    // local definitions by its config header.
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
    "-Wl,--max-memory=1048576",
    "-o",
    out,
    resolve(src, cfg.cSource),
    resolve(pq, cfg.shim),
  ];

  // `bash -lc` with the command quoted here rather than `wsl clang …`: wsl.exe re-parses
  // the command line Node builds, and the config define carries quotes the preprocessor
  // needs, so one already-quoted string is the only way those survive.
  const native = process.env.CC ?? (process.platform === "win32" ? null : "clang");
  if (native) {
    execFileSync(native, args, { stdio: "inherit" });
  } else {
    const cmd = ["clang", ...args.map(toWslPath)]
      .map((a) => `'${a.replace(/'/g, `'\\''`)}'`)
      .join(" ");
    execFileSync("wsl", ["bash", "-lc", cmd], { stdio: "inherit" });
  }
  console.log(`wrote ${statSync(out).size} bytes -> ${cfg.out}`);
}
