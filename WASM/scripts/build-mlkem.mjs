// Builds browser/mlkem768.wasm, ML-KEM-768 (FIPS 203) as an import-free pure module
// shipped in the transport bundle, from the pinned mlkem-native submodule. The same
// artifact runs on every target, so handshake results cannot depend on the target.
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
