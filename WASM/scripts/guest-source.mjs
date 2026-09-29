// The transport bundle's guest program: transport/src/*.js concatenated in a fixed order
// (util, ake, framing, router, rtc, core). The order matters (the parts share one scope,
// and "use strict" must come first), and this is the only list of parts. The op-frame
// source replaces the marker in util.js. No dependencies, so loc.mjs can use the path list.

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

/** The assembled guest program as text, which is what the manifest signs; verification
 *  decodes the packed guest back to text. `opFrameSource` comes from bundle-author.ts's
 *  `guestOpFraming`, which serializes the services/op-frame.ts functions.
 *
 *  The result is normalized to LF because this text is signed: `.gitattributes` checks
 *  the parts out LF, but an editor can still save CRLF in the working tree, and the same
 *  commit must sign the same bytes on every machine. Raw newlines here only appear in
 *  comments and whitespace (the JS parser normalizes template literals anyway), so this
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
