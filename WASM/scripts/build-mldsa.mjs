// Builds browser/mldsa65.wasm — the ML-DSA-65 verifier for manifest suite 0x02
// (§12.4, §14.1) — from the pinned mldsa-native submodule; see build-pq-wasm.mjs for the
// shared flag set. ONE artifact for all three targets, so the accept/reject boundary
// cannot drift between a node that admits a bundle and one that refuses it.
import { buildPqWasm } from "./build-pq-wasm.mjs";

buildPqWasm({
  submodule: "mldsa-native",
  marker: "mldsa/mldsa_native.c",
  cSource: "mldsa/mldsa_native.c",
  incDir: "mldsa",
  configDefine: "MLD_CONFIG_FILE",
  configHeader: "config.h",
  shim: "shim.c",
  out: "browser/mldsa65.wasm",
});
