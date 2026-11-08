// The transport bundle's guest program: transport/src/*.js concatenated in a fixed order
// (util, ake, framing, router, relay, quic, udp, direct, core). The order matters (the
// parts share one scope, and "use strict" must come first), and this is the only list of
// parts. The op-frame source replaces the marker in util.js. No dependencies, so loc.mjs
// can use the path list. The first three are the channel alone (`readChannelSource`),
// which a relay (seedrelay) runs as the responder of every relay link.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const GUEST_PARTS = ["util.js", "ake.js", "framing.js", "router.js", "relay.js", "quic.js", "udp.js", "direct.js", "core.js"];
const OP_FRAME_MARKER = "/* @seedkernel-op-frame */";

/** The channel: the helpers, the link with its handshake and records, and the framers. */
export const CHANNEL_PARTS = GUEST_PARTS.slice(0, 3);

/** Absolute paths to the parts, in concatenation order. */
export function guestSourcePaths(parts = GUEST_PARTS) {
  return parts.map((f) => join(wasmDir, "transport", "src", f));
}

/** The assembled guest program as text, which is what the manifest signs; verification
 *  decodes the packed guest back to text. `opFrameSource` comes from bundle-author.ts's
 *  `guestOpFraming`, which serializes the host/op-frame.ts functions.
 *
 *  The result is normalized to LF because this text is signed: `.gitattributes` checks
 *  the parts out LF, but an editor can still save CRLF in the working tree, and the same
 *  commit must sign the same bytes on every machine. Raw newlines here only appear in
 *  comments and whitespace (the JS parser normalizes template literals anyway), so this
 *  cannot change what the program does. */
export function readGuestSource(opFrameSource, parts = GUEST_PARTS) {
  if (typeof opFrameSource !== "string" || opFrameSource.trim().length === 0) {
    throw new Error("guest source: canonical op-frame source is required");
  }
  const guest = Buffer.concat(guestSourcePaths(parts).map((p) => readFileSync(p))).toString();
  const at = guest.indexOf(OP_FRAME_MARKER);
  if (at < 0) throw new Error(`guest source: no ${OP_FRAME_MARKER} marker to inject the op-frame at`);
  if (guest.indexOf(OP_FRAME_MARKER, at + OP_FRAME_MARKER.length) >= 0) {
    throw new Error(`guest source: ${OP_FRAME_MARKER} appears more than once — the op-frame would be defined twice`);
  }
  const whole = guest.slice(0, at) + opFrameSource + guest.slice(at + OP_FRAME_MARKER.length);
  return whole.replace(/\r\n/g, "\n");
}

/** The channel's parts (`CHANNEL_PARTS`) assembled as `readGuestSource` assembles the
 *  whole transport, for a program that runs the link itself and supplies, before using it,
 *  the settings core.js otherwise declares (seedrelay's guest names them). */
export function readChannelSource(opFrameSource) {
  return readGuestSource(opFrameSource, CHANNEL_PARTS);
}
