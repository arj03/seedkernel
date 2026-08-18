// Builds browser/mldsa65.wasm — the ML-DSA-65 verifier for manifest suite 0x02
// (§12.4, §14.1) — from the pinned mldsa-native submodule in pq/mldsa-native.
// The flag set and the build plumbing are shared with its sibling build-mlkem.mjs
// (see scripts/build-pq-wasm.mjs); only the sources differ.
//
// ONE artifact for all three targets (native/mldsa.go is fed by copy-loader-wasm.mjs):
// the same bytes, so the accept/reject boundary cannot drift between a node that admits
// a bundle and a node that refuses it. Same reason Ed25519 stays on the shared
// libsodium.wasm rather than each target's native implementation.
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
