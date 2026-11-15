// Extracts browser/libsodium.wasm, the host's crypto every host blob carries
// (scripts/build-host-blob.mjs), from the upstream libsodium-sumo npm dist, where it is
// embedded as base64: sumo, not core, for crypto_hash_sha256. host/sodium-engine.ts drives
// it by the dist's minified export names.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const core = readFileSync(resolve(root, "node_modules/libsodium-sumo/dist/modules-sumo-esm/libsodium-sumo.mjs"), "utf8");

// The embedded WASM is a base64 string literal beginning "AGFzbQ" (the "\0asm" magic).
const b64Start = core.indexOf('"AGFzbQ');
if (b64Start < 0) throw new Error("could not locate base64 WASM string in libsodium-sumo.mjs");
const b64End = core.indexOf('"', b64Start + 1);
if (b64End < 0) throw new Error("unterminated base64 WASM string");

const wasm = Buffer.from(core.slice(b64Start + 1, b64End), "base64");
writeFileSync(resolve(root, "browser", "libsodium.wasm"), wasm);
console.log(`wrote ${wasm.length} bytes -> browser/libsodium.wasm`);
