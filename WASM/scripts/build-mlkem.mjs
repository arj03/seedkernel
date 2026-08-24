// Builds browser/mlkem768.wasm — ML-KEM-768 (FIPS 203) as an import-free pure module
// carried by the transport bundle — from the pinned mlkem-native submodule.
// One artifact rides in the same signed bundle on every target, so a rejected encoding
// cannot become a target-dependent handshake result.
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
