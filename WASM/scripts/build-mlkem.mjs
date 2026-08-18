// Builds browser/mlkem768.wasm — ML-KEM-768 (FIPS 203) for the primitive catalog
// (`ml-kem-768/*`, README §14.1) — from the pinned mlkem-native submodule in
// pq/mlkem-native. The flag set and the build plumbing are shared with its sibling
// build-mldsa.mjs (see scripts/build-pq-wasm.mjs); only the sources differ.
//
// ONE artifact for all three targets (native/mlkem.go is fed by copy-loader-wasm.mjs),
// but for a different reason than ML-DSA's: a KEM is not a verifier, so its
// accept/reject boundary is not consensus. What makes it one artifact is that a catalog
// entry is a *name* two nodes hand each other bytes under (§12.6) — two implementations
// disagreeing on a rejected encoding simply fail to share a key, and the cheapest way
// not to find that out in production is not to have two.
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
