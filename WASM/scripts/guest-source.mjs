// The transport bundle's guest program: transport/src/*.js concatenated in a FIXED order
// (util → ake → framing → router → rtc → core). Order is load-bearing (parts share one scope,
// "use strict" leads), and the parts live ONLY here. The canonical op-frame fragment
// replaces the marker util.js carries. Dependency-free so loc.mjs can use its path list.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const GUEST_PARTS = ["util.js", "ake.js", "framing.js", "router.js", "rtc.js", "core.js"];
const OP_FRAME_MARKER = "/* @seedkernel-op-frame */";

/** Absolute paths to the parts, in concatenation order. */
export function guestSourcePaths() {
  return GUEST_PARTS.map((f) => join(wasmDir, "transport", "src", f));
}

/** The assembled guest program as text — the shape the manifest hashes; verification
 *  decodes the packed guest back to text, so text is the only shape that round-trips.
 *  `opFrameSource` comes from bundle-author.ts's `guestOpFraming`, which serializes the
 *  canonical services/op-frame.ts functions.
 *
 *  The result is normalized to LF because this text is SIGNED: `.gitattributes` checks the
 *  parts out LF, but the build reads the working tree, where an editor can still save CRLF,
 *  and the same commit must sign the same bytes on every machine. Only comments hold a raw
 *  newline here — a template literal's would be normalized by the JS parser anyway — so it
 *  cannot change what the program does. */
export function readGuestSource(opFrameSource) {
  if (typeof opFrameSource !== "string" || opFrameSource.trim().length === 0) {
    throw new Error("guest source: canonical op-frame source is required");
  }
  const guest = Buffer.concat(guestSourcePaths().map((p) => readFileSync(p))).toString();
  const at = guest.indexOf(OP_FRAME_MARKER);
  if (at < 0) throw new Error(`guest source: no ${OP_FRAME_MARKER} marker to inject the op-frame at`);
  if (guest.indexOf(OP_FRAME_MARKER, at + OP_FRAME_MARKER.length) >= 0) {
    throw new Error(`guest source: ${OP_FRAME_MARKER} appears more than once — the op-frame would be defined twice`);
  }
  const whole = guest.slice(0, at) + opFrameSource + guest.slice(at + OP_FRAME_MARKER.length);
  return whole.replace(/\r\n/g, "\n");
}
