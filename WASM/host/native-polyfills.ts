// The Web globals the shared host code uses that quickjs-ng lacks, each filled only where
// the loader's engine has none: all of them on native, none on Node. Guest realms get only
// ECMAScript intrinsics on every target (§12.3).
//
// Second in the host script, after the UTF-8 codec it fills TextEncoder and TextDecoder
// with, so the globals exist before any module uses one at load time
// (host/domains.ts builds its DOMAIN constants with a `TextEncoder` at module scope).
import { utf8Decode, utf8Encode } from "./utf8.js";

/** The `bridge` members this file uses (abi.ts declares the whole of it). */
declare const bridge: { log(line: string): void };

const web = globalThis as { TextEncoder?: unknown; TextDecoder?: unknown; console?: unknown };

// The guests' codec, so the host and its guests agree on every string.
if (web.TextEncoder === undefined) {
  web.TextEncoder = class TextEncoder {
    encode(input: string): Uint8Array { return utf8Encode(String(input)); }
  };
}

if (web.TextDecoder === undefined) {
  web.TextDecoder = class TextDecoder {
    decode(buf?: ArrayBuffer | ArrayLike<number>): string {
      return utf8Decode(buf instanceof Uint8Array ? buf : new Uint8Array(buf ?? []));
    }
  };
}

// console: quickjs-ng defines none, and shared host code logs through it (for example
// when reporting a wedged transport guest). Everything goes to stderr through
// `bridge.log`, because stdout carries the app's raw response bytes for --op.
if (web.console === undefined) {
  const show = (a: unknown): string => {
    if (typeof a === "string") return a;
    // Message first: quickjs's `stack` holds only the frames, not the message.
    if (a instanceof Error) return a.stack ? String(a) + "\n" + a.stack : String(a);
    try {
      const j = JSON.stringify(a);
      if (j !== undefined) return j;
    } catch { /* cyclic, or a throwing toJSON: fall through to String */ }
    return String(a);
  };
  const sink = (...args: unknown[]): void => { bridge.log(args.map(show).join(" ")); };
  web.console = { log: sink, info: sink, debug: sink, warn: sink, error: sink, trace: sink };
}
