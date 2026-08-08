// The few Web globals the shared host code assumes and quickjs-ng does not provide —
// the native target's, and only the native target's (a browser and Node have all of
// them). Both of that target's realms take them from here: the host realm by evaluating
// this module, the confined realm by evaluating the same text (native/guest.go).
//
// These are ordinary JavaScript that has to behave the same on every target, and one
// text serves both realms — the point of the string: the host realm cannot fetch it
// from the shell (the shell IS what needs it — `core/domains.ts` builds its DOMAIN
// constants with a `TextEncoder` at module scope), so this module is first in the
// loader bundle and installs them on the way past. A second, TypeScript-typed copy for
// the host realm would be two implementations of one polyfill, which is the shape this
// file prevents.
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

  // atob — the artifact-embedded transport bundle is inlined as base64
  // (transport-bundle.ts) and decoded at module scope. Without this the decode threw,
  // the blob read as ABSENT, and the node came up with no network at all — which is
  // also what a deliberate deny-all policy looks like, so nothing said so.
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

  // console — quickjs-ng's own has \`log\` and nothing else, and writes it to a WASI
  // stdout wazero leaves disconnected. So on this target console.log was discarded and
  // console.error threw a TypeError *inside* the handler that reports a wedged transport
  // guest (transport-host.ts): the one diagnostic that says the network is stuck was
  // invisible twice over, once silently and once as a different error.
  //
  // Everything here goes to STDERR, through the bridge rather than the WASI fd — which
  // is also why the fd stays disconnected. Stdout is the operator's channel: it carries
  // \`bridge.log\`'s lines and, for --get with no --out, the app's raw response bytes, and
  // a diagnostic interleaved into that corrupts a piped response.
  //
  // Guarded on the bridge, so this replaces console only in the HOST realm. A confined
  // guest has no bridge and keeps quickjs's discarding console, which is the closer
  // match to the JS target, where a guest realm holds the ECMAScript intrinsics and no
  // console at all (safe-js.ts).
  if (typeof bridge !== "undefined" && typeof bridge.logErr === "function") {
    const show = (a) => {
      if (typeof a === "string") return a;
      // Message first, then the frames: quickjs's \`stack\` is the frames ALONE, so
      // printing it by itself drops the only part that says what went wrong.
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

/** The same text, for the confined realm — fetched by Go the way `guestPreamble` and
 *  `guestDriver` are, before it evaluates either of them into a fresh QuickJS context
 *  (native/guest.go). A guest gets the encoders and the microtask queue; the console
 *  branch above no-ops there, since a confined realm holds no bridge. */
export function nativePolyfills(): string {
    return POLYFILLS;
}
