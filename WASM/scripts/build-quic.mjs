// Builds transport/quic/quic.wasm, the QUIC connection of the transport's UDP paths
// (transport/quic/quic.c over ngtcp2), as an import-free pure module (§4) shipped in the
// transport bundle. The artifact is committed, as browser/mlkem768.wasm is, so a build
// needs no C toolchain; this rebuilds it after quic.c, scratch.wat or a pin in build.sh
// changes.
//
// Requires wasi-sdk, binaryen (wasm-as, wasm-merge, wasm-opt), cmake and git. On Windows it
// runs in WSL, as build-pq-wasm.mjs does.
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = resolve(root, "transport", "quic", "build.sh");
const out = resolve(root, "transport", "quic", "quic.wasm");

/** `C:\dir\file` to `/mnt/c/dir/file`. */
const toWslPath = (p) => p.replace(/^([A-Za-z]):\\/, (_, d) => `/mnt/${d.toLowerCase()}/`).replace(/\\/g, "/");

if (process.platform === "win32") {
  execFileSync("wsl", ["bash", "-lc", `bash '${toWslPath(script)}' '${toWslPath(out)}'`], { stdio: "inherit" });
} else {
  execFileSync("bash", [script, out], { stdio: "inherit" });
}
console.log(`  quic.wasm: ${out}`);
