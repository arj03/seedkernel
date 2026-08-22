// The transport bundle's guest program, as an ordered list of its parts.
//
// The guest is not one file on disk: it is the concatenation of transport/src/*.js in a
// fixed order (util → ake → framing → router → core), assembled at build time into the
// single program the manifest hashes and the loader runs. Order is load-bearing —
// util.js leads the program, since its "use strict" is the first statement — and the
// parts share one scope, so a part may depend on an earlier one at runtime but never at
// top level.
//
// The order lives HERE and only here, because three callers must agree on it and two
// sign over the result: build-transport-bundle.mjs (the shipped artifact),
// tests/transport-bundle.test.mjs (its own upgrade bundles) and loc.mjs (the README
// row). A second copy would sign a different program than production the moment the
// split moved, surfacing as a hash mismatch rather than as the drift it was.
//
// Deliberately dependency-free: loc.mjs should not load a crypto library to learn five
// filenames.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const GUEST_PARTS = ["util.js", "ake.js", "framing.js", "router.js", "core.js"];

/** Absolute paths to the parts, in concatenation order. */
export function guestSourcePaths() {
  return GUEST_PARTS.map((f) => join(wasmDir, "transport", "src", f));
}

/** The assembled guest program as TEXT — the exact source the manifest hashes (as UTF-8)
 *  and the loader runs. `authorBundle` takes this string: verification decodes the
 *  packed guest back to text before re-checking it, so text is the only shape that can
 *  round-trip. */
export function readGuestSource() {
  return Buffer.concat(guestSourcePaths().map((p) => readFileSync(p))).toString();
}
