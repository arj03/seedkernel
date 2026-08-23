// The transport bundle's guest program: transport/src/*.js concatenated in a FIXED order
// (util → ake → framing → router → core). Order is load-bearing (parts share one scope,
// "use strict" leads), and the parts live ONLY here — three callers must agree on them,
// or a second copy would sign a different program than production. Dependency-free so
// loc.mjs can use it.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const GUEST_PARTS = ["util.js", "ake.js", "framing.js", "router.js", "core.js"];

/** Absolute paths to the parts, in concatenation order. */
export function guestSourcePaths() {
  return GUEST_PARTS.map((f) => join(wasmDir, "transport", "src", f));
}

/** The assembled guest program as text — the shape the manifest hashes; verification
 *  decodes the packed guest back to text, so text is the only shape that round-trips. */
export function readGuestSource() {
  return Buffer.concat(guestSourcePaths().map((p) => readFileSync(p))).toString();
}
