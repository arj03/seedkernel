// Bun-only genesis-module loader. kernel.wasm + bootstrap.wasm are imported with
// the Bun "file" loader, so `bun build --compile` embeds their bytes *inside* the
// executable; each import resolves to a path that fs.readFile serves from the
// virtual bundle at runtime (and from disk during `bun run`). This is the one
// piece the shared node loader can't provide. The file is excluded from the
// *emit* build (Node must never load it) but typechecked by tsconfig.check.json;
// only the two asset imports themselves are suppressed — tsc cannot resolve a
// .wasm specifier into the generated build dir.

import { readFile } from "node:fs/promises";

// @ts-expect-error Bun asset import — resolves to a path string at runtime
import kernelPath from "../build/kernel.wasm" with { type: "file" };
// @ts-expect-error Bun asset import — resolves to a path string at runtime
import bootstrapPath from "../build/bootstrap.wasm" with { type: "file" };

import type { KernelWasm } from "./main.js";

export async function loadKernelWasmEmbedded(): Promise<KernelWasm> {
  const [k, b] = await Promise.all([readFile(kernelPath), readFile(bootstrapPath)]);
  return { kernelBytes: new Uint8Array(k), bootstrapBytes: new Uint8Array(b) };
}
