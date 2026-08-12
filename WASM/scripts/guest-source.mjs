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

/** The seam version this program is written against, read out of `core/domains.ts`.
 *
 *  From the SOURCE rather than from `build/`, because the bundle is assembled before
 *  tsc runs — the generated `host/transport-bundle.ts` is one of tsc's inputs — so the
 *  compiled constant does not exist yet at this point in the build. A regex over one
 *  `export const` line is the whole of the dependency, and it throws rather than
 *  defaulting: a bundle declaring an ABI its guest was not written against is exactly
 *  the silent failure `guest.abi` exists to make loud (§12.4). */
export function readGuestAbi() {
  const src = readFileSync(join(wasmDir, "core", "domains.ts"), "utf8");
  const m = /^export const GUEST_ABI_VERSION = (\d+);$/m.exec(src);
  if (!m) throw new Error("guest-source: could not read GUEST_ABI_VERSION from core/domains.ts");
  return Number(m[1]);
}
