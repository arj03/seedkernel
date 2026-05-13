// Builds browser/libsodium.wasm + browser/libsodium-core.mjs +
// browser/libsodium-wrappers.mjs from the upstream libsodium-wrappers package.
//
// Why: the npm dist embeds the WASM as a 295KB base64 string inside the JS.
// We strip that out and ship the raw .wasm so the browser can fetch it
// directly (smaller payload, browser caches the .wasm separately, no decode
// cost on every load).

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const coreSrc = resolve(root, "node_modules/libsodium/dist/modules-esm/libsodium.mjs");
const wrapSrc = resolve(root, "node_modules/libsodium-wrappers/dist/modules-esm/libsodium-wrappers.mjs");
const outDir = resolve(root, "browser");

const core = readFileSync(coreSrc, "utf8");

// Locate the IIFE that decodes the embedded base64. Pattern (minified):
//   (F??=(A=>{for(var I,g,C=0,B=0,Q=<size>,E=new Uint8Array(<rawSize>-...);...})("AGFzbQ...="),
const iifeStart = core.indexOf("(F??=(A=>{for(var ");
if (iifeStart < 0) throw new Error("could not locate base64-decoder IIFE in libsodium.mjs");
const b64Start = core.indexOf('"AGFzbQ', iifeStart);
if (b64Start < 0) throw new Error("could not locate base64 WASM string");
const b64End = core.indexOf('"', b64Start + 1);
if (b64End < 0) throw new Error("unterminated base64 string");
const iifeEnd = core.indexOf("),", b64End) + 1; // closing ) of the IIFE call

const b64 = core.slice(b64Start + 1, b64End);
const wasm = Buffer.from(b64, "base64");
writeFileSync(resolve(outDir, "libsodium.wasm"), wasm);

// Replace the IIFE expression with a no-op Uint8Array. F is unused when the
// caller passes instantiateWasm (which our wrapper does), but keeping the
// assignment shape preserves the surrounding comma-operator chain.
const patchedCore =
  core.slice(0, iifeStart) +
  "(F??=new Uint8Array(0)" +
  core.slice(iifeEnd);
writeFileSync(resolve(outDir, "libsodium-core.mjs"), patchedCore);

// Patch the wrappers: redirect the bare "libsodium" import at our local core,
// and inject an instantiateWasm callback that fetches the .wasm file.
const wrap = readFileSync(wrapSrc, "utf8");
const wrapPatched = wrap
  .replace('import e from"libsodium"', 'import e from"./libsodium-core.mjs"')
  .replace(
    "e({getRandomValue:function(){",
    "e({instantiateWasm:async(imports,cb)=>{" +
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
