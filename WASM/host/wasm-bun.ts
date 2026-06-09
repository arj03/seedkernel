// Bun-only genesis-module loader. kernel.wasm + bootstrap.wasm are imported with
// the Bun "file" loader, so `bun build --compile` embeds their bytes *inside* the
// executable; each import resolves to a path that fs.readFile serves from the
// virtual bundle at runtime (and from disk during `bun run`). This is the one
// piece the shared node loader can't provide — `with { type: "file" }` is a Bun
// loader and Node would reject it at parse time (so this file is excluded from
// the tsc host build).

import { readFile } from "node:fs/promises";

import kernelPath from "../build/kernel.wasm" with { type: "file" };
import bootstrapPath from "../build/bootstrap.wasm" with { type: "file" };

import type { KernelWasm } from "./main.js";

export async function loadKernelWasmEmbedded(): Promise<KernelWasm> {
  const [k, b] = await Promise.all([readFile(kernelPath), readFile(bootstrapPath)]);
  return { kernelBytes: new Uint8Array(k), bootstrapBytes: new Uint8Array(b) };
}
