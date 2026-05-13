// Append a UI custom section to a .wasm file.
//
// WebAssembly custom sections are skipped by `WebAssembly.instantiate` and
// recoverable via `WebAssembly.Module.customSections(module, name)`. Bundling
// the chat UI bytes inside the chat-app WASM means a single signed install
// message updates compute and presentation atomically — exactly the property
// described in README §3.2 (one artifact, one install policy, one revocation).
//
// Section layout (per spec):
//   id:            0x00 (custom)
//   section_size:  LEB128
//   name_len:      LEB128
//   name:          UTF-8 bytes
//   payload:       arbitrary bytes
//
// We append at the end of the file — the spec allows custom sections at any
// position, but appending is the least likely to surprise tools that only
// validate the standard section ordering.
//
// Usage:  node scripts/embed-ui.mjs <wasm-in> <ui-in> <wasm-out> [section-name=ui]

import { readFileSync, writeFileSync } from "node:fs";

const [, , wasmPath, uiPath, outPath, sectionNameArg] = process.argv;
if (!wasmPath || !uiPath || !outPath) {
  console.error("usage: node scripts/embed-ui.mjs <wasm-in> <ui-in> <wasm-out> [name=ui]");
  process.exit(2);
}
const sectionName = sectionNameArg || "ui";

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

const wasm    = new Uint8Array(readFileSync(wasmPath));
const ui      = new Uint8Array(readFileSync(uiPath));
const nameUtf = new TextEncoder().encode(sectionName);

// section payload = name_len(LEB128) + name + ui
const inner = concat(leb128(nameUtf.length), nameUtf, ui);
// full section = id(0x00) + size(LEB128) + payload
const section = concat(new Uint8Array([0x00]), leb128(inner.length), inner);
const out = concat(wasm, section);

writeFileSync(outPath, out);
console.log(`embed-ui: ${wasmPath} + ${uiPath} → ${outPath} (` +
  `${wasm.length} + ${ui.length} bytes UI, section "${sectionName}", ` +
  `total ${out.length})`);
