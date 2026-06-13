// Builds browser/libsodium.wasm + browser/libsodium-core.mjs +
// browser/libsodium-wrappers.mjs from the upstream libsodium-wrappers-sumo
// package — the one libsodium the runtime depends on (PLAN-runtime-split.md §3).
//
// Why: the npm dist embeds the WASM as a base64 string inside the JS. We strip
// that string out and ship the raw .wasm so the browser fetches it directly
// (smaller payload, the browser caches the .wasm separately, no base64 decode
// cost on every load). The embedded decoder is left in place but fed an empty
// string — robust against the exact minified shape — since the patched wrapper
// supplies its own instantiateWasm and never reads the decoder's output.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const coreSrc = resolve(root, "node_modules/libsodium-sumo/dist/modules-sumo-esm/libsodium-sumo.mjs");
const wrapSrc = resolve(root, "node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs");
const outDir = resolve(root, "browser");

const core = readFileSync(coreSrc, "utf8");

// The embedded WASM is a base64 string literal beginning "AGFzbQ" (the "\0asm"
// magic). Extract it for the standalone .wasm, then blank the literal in the
// core so the shipped core.mjs no longer carries ~300 KB of dead base64.
const b64Start = core.indexOf('"AGFzbQ');
if (b64Start < 0) throw new Error("could not locate base64 WASM string in libsodium-sumo.mjs");
const b64End = core.indexOf('"', b64Start + 1);
if (b64End < 0) throw new Error("unterminated base64 WASM string");

const b64 = core.slice(b64Start + 1, b64End);
const wasm = Buffer.from(b64, "base64");
writeFileSync(resolve(outDir, "libsodium.wasm"), wasm);

const patchedCore = core.slice(0, b64Start) + '""' + core.slice(b64End + 1);
writeFileSync(resolve(outDir, "libsodium-core.mjs"), patchedCore);

// Patch the wrappers: redirect the bare "libsodium-sumo" core import at our local
// stripped core, and inject an instantiateWasm callback that fetches the .wasm.
// The sumo wrappers invoke the core as `a({getRandomValue:function(){…}})`.
const wrap = readFileSync(wrapSrc, "utf8");
const wrapPatched = wrap
  .replace('import e from"libsodium-sumo"', 'import e from"./libsodium-core.mjs"')
  .replace(
    "a({getRandomValue:function(){",
    "a({instantiateWasm:async(imports,cb)=>{" +
      "const r=await fetch(new URL('./libsodium.wasm',import.meta.url));" +
      "const{instance}=await WebAssembly.instantiateStreaming(r,imports);" +
      "cb(instance);" +
    "},getRandomValue:function(){"
  );
if (wrapPatched === wrap) throw new Error("wrappers patch failed — upstream layout changed?");
writeFileSync(resolve(outDir, "libsodium-wrappers.mjs"), wrapPatched);

console.log(`wrote ${wasm.length} bytes -> browser/libsodium.wasm`);
console.log(`wrote ${patchedCore.length} bytes -> browser/libsodium-core.mjs (was ${core.length})`);
console.log(`wrote ${wrapPatched.length} bytes -> browser/libsodium-wrappers.mjs`);
