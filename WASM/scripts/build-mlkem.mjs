// Builds browser/mlkem768.wasm — ML-KEM-768 (FIPS 203) for the primitive catalog
// (`ml-kem-768/*`, §14.1) — from the pinned mlkem-native submodule; see build-pq-wasm.mjs
// for the shared flag set. ONE artifact for all three targets: a catalog entry is a name
// two nodes exchange bytes under (§12.6), so two implementations disagreeing on a
// rejected encoding would simply fail to share a key in production.
import { buildPqWasm } from "./build-pq-wasm.mjs";

buildPqWasm({
  submodule: "mlkem-native",
  marker: "mlkem/mlkem_native.c",
  cSource: "mlkem/mlkem_native.c",
  incDir: "mlkem",
  configDefine: "MLK_CONFIG_FILE",
  configHeader: "kem-config.h",
  shim: "kem-shim.c",
  out: "browser/mlkem768.wasm",
});
