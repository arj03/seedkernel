// The few Web globals the shared host code assumes and quickjs-ng does not provide — the
// native target's and only the native target's (browser and Node have all of them). Both
// of that target's realms take them from here: the host realm by evaluating this module,
// the confined realm by evaluating the same text (native/guest.go).
//
// One text serves both realms: the host realm cannot fetch it from the shell, because the
// shell IS what needs it (core/domains.ts builds its DOMAIN constants with a
// `TextEncoder` at module scope), so this module is first in the loader bundle. A second
// typed copy for the host realm would be two implementations of one polyfill.
const POLYFILLS = `
"use strict";
(function () {
  if (typeof globalThis.TextEncoder === "undefined") {
    globalThis.TextEncoder = class TextEncoder {
      encode(s) {
        s = String(s);
        const out = [];
        for (let i = 0; i < s.length; i++) {
          let c = s.charCodeAt(i);
          if (c < 0x80) out.push(c);
          else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
          else if (c >= 0xd800 && c <= 0xdbff) {
            const c2 = s.charCodeAt(++i);
            c = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
            out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
          } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
        }
        return new Uint8Array(out);
      }
    };
  }
  if (typeof globalThis.TextDecoder === "undefined") {
    globalThis.TextDecoder = class TextDecoder {
      decode(buf) {
        const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf || 0);
        let s = "";
        for (let i = 0; i < b.length; ) {
          let c = b[i++];
          if (c >= 0x80) {
            if (c < 0xe0) c = ((c & 0x1f) << 6) | (b[i++] & 0x3f);
            else if (c < 0xf0) c = ((c & 0x0f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f);
            else {
              c = ((c & 0x07) << 18) | ((b[i++] & 0x3f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f);
              c -= 0x10000;
              s += String.fromCharCode(0xd800 + (c >> 10), 0xdc00 + (c & 0x3ff));
              continue;
            }
          }
          s += String.fromCharCode(c);
        }
        return s;
      }
    };
  }

  // atob — the embedded transport bundle is inlined as base64 and decoded at module scope.
  // Without this the blob read as ABSENT and the node came up with no network — which is
  // also what a deliberate deny-all policy looks like.
  if (typeof globalThis.atob === "undefined") {
    const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    globalThis.atob = function (b64) {
      let out = "", bits = 0, acc = 0;
      for (let i = 0; i < b64.length; i++) {
        const c = b64[i];
        if (c === "=" || c === "\\n" || c === "\\r") continue;
        const v = B64.indexOf(c);
        if (v < 0) throw new Error("atob: bad base64 character");
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
          bits -= 8;
          out += String.fromCharCode((acc >> bits) & 0xff);
        }
      }
      return out;
    };
  }

  // queueMicrotask — the transport driver's deliver path answers on a LATER turn, so
  // that no op re-enters a live guest frame. Without it the turn boundary is gone.
  if (typeof globalThis.queueMicrotask === "undefined") {
    globalThis.queueMicrotask = function (fn) { Promise.resolve().then(fn); };
  }

  // console — quickjs-ng's own has \`log\` and nothing else, written to a WASI stdout wazero
  // leaves disconnected: console.log was discarded and console.error threw a TypeError
  // *inside* the handler that reports a wedged transport guest.
  //
  // Everything here goes to STDERR through the bridge, because stdout is the operator's
  // channel — it carries \`bridge.log\` and, for --op, the app's raw response bytes. Guarded
  // on the bridge, so only the HOST realm gets it; a confined guest keeps quickjs's
  // discarding console, matching the JS target's realm holding no console at all.
  if (typeof bridge !== "undefined" && typeof bridge.logErr === "function") {
    const show = (a) => {
      if (typeof a === "string") return a;
      // Message first: quickjs's \`stack\` is the frames ALONE, so printing it by itself
      // drops the part that says what went wrong.
      if (a instanceof Error) return a.stack ? String(a) + "\\n" + a.stack : String(a);
      try {
        const j = JSON.stringify(a);
        if (j !== undefined) return j;
      } catch (e) { /* cyclic, or a toJSON that throws — fall through to String */ }
      return String(a);
    };
    const emit = (args) => {
      let line = "";
      for (let i = 0; i < args.length; i++) line += (i ? " " : "") + show(args[i]);
      bridge.logErr(line);
    };
    const sink = function () { emit(arguments); };
    globalThis.console = {
      log: sink, info: sink, debug: sink, warn: sink, error: sink, trace: sink,
    };
  }
})();
`;

// The host realm, on the way past: this module is FIRST in `build:loader-bundles`, so
// the globals exist before any module that reaches for one at load time. Indirect eval
// so the declarations land on globalThis rather than in this module's own scope — the
// bundler gives every module a scope of its own (scripts/bundle-loader.mjs).
(0, eval)(POLYFILLS);

/** The same text for the confined realm — fetched by Go the way `guestPreamble` and
 *  `guestDriver` are (native/guest.go). A guest gets the encoders and the microtask queue;
 *  the console branch no-ops there, since a confined realm holds no bridge. */
export function nativePolyfills(): string {
    return POLYFILLS;
}
