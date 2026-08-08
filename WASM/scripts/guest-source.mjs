// The transport bundle's guest program, as an ordered list of its parts.
//
// The guest is not one file on disk: it is the concatenation of transport/src/*.js in a
// fixed order (util → ake → framing → router → core), assembled at build time into the
// single program the manifest hashes and the loader runs. Order is load-bearing —
// util.js leads the program (its "use strict" directive is the first statement), and a
// part may depend on an earlier one at runtime but never at top level. The parts share
// one scope, so this is a source-organisation split and nothing else.
//
// The order lives HERE and only here, because three callers must agree on it and two of
// them sign over the result: scripts/build-transport-bundle.mjs (the shipped artifact),
// tests/transport-bundle.test.mjs (the upgrade bundles it signs under its own keys), and
// scripts/loc.mjs (the README row). A second copy of the list would sign a different
// program than production the moment the split moved, and it would surface as a hash
// mismatch rather than as the drift it was.
//
// This module is deliberately dependency-free: loc.mjs should not load a crypto library
// to learn five filenames.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const GUEST_PARTS = ["util.js", "ake.js", "framing.js", "router.js", "core.js"];

/** Absolute paths to the parts, in concatenation order. */
export function guestSourcePaths() {
  return GUEST_PARTS.map((f) => join(wasmDir, "transport", "src", f));
}

/** The assembled guest program — the exact bytes the manifest hashes. */
export function readGuestSource() {
  return Buffer.concat(guestSourcePaths().map((p) => readFileSync(p)));
}
