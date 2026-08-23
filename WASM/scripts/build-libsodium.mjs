// Extracts browser/libsodium.wasm from the upstream libsodium-wrappers-sumo npm dist and
// patches the wrapper so the browser fetches the raw .wasm instead of base64-decoding it
// per load. The embedded decoder stays (fed ""); the wrapper's own instantiateWasm never
// reads its output.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const coreSrc = resolve(root, "node_modules/libsodium-sumo/dist/modules-sumo-esm/libsodium-sumo.mjs");
const wrapSrc = resolve(root, "node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs");
const outDir = resolve(root, "browser");

const core = readFileSync(coreSrc, "utf8");

// The embedded WASM is a base64 string literal beginning "AGFzbQ" (the "\0asm" magic):
// extract it for the standalone .wasm, then blank the literal in the core.
const b64Start = core.indexOf('"AGFzbQ');
if (b64Start < 0) throw new Error("could not locate base64 WASM string in libsodium-sumo.mjs");
const b64End = core.indexOf('"', b64Start + 1);
if (b64End < 0) throw new Error("unterminated base64 WASM string");

const b64 = core.slice(b64Start + 1, b64End);
const wasm = Buffer.from(b64, "base64");
writeFileSync(resolve(outDir, "libsodium.wasm"), wasm);

const patchedCore = core.slice(0, b64Start) + '""' + core.slice(b64End + 1);
writeFileSync(resolve(outDir, "libsodium-core.mjs"), patchedCore);

// Patch the wrapper: import our stripped core, and inject an instantiateWasm that fetches
// the .wasm — the sumo wrappers invoke the core as `a({getRandomValue:function(){…}})`.
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
