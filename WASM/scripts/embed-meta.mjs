// Append an `app_meta` custom section to a .wasm file. The section payload is
// the UTF-8 JSON given on the command line. The shell reads this section via
// `WebAssembly.Module.customSections(mod, "app_meta")` so a dropped artifact
// can identify itself without the user having to type metadata in by hand.
//
// Usage:  node scripts/embed-meta.mjs <wasm-in> <wasm-out> '<json>'

import { readFileSync, writeFileSync } from "node:fs";

const [, , wasmPath, outPath, json] = process.argv;
if (!wasmPath || !outPath || !json) {
  console.error("usage: node scripts/embed-meta.mjs <wasm-in> <wasm-out> '<json>'");
  process.exit(2);
}
JSON.parse(json); // validate

function leb128(n) {
  const bytes = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    bytes.push(b);
  } while (n !== 0);
  return new Uint8Array(bytes);
}
function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const wasm = new Uint8Array(readFileSync(wasmPath));
const nameUtf = new TextEncoder().encode("app_meta");
const payload = new TextEncoder().encode(json);
const inner = concat(leb128(nameUtf.length), nameUtf, payload);
const section = concat(new Uint8Array([0x00]), leb128(inner.length), inner);
writeFileSync(outPath, concat(wasm, section));
console.log(`embed-meta: ${wasmPath} → ${outPath} (+${payload.length} bytes app_meta)`);
