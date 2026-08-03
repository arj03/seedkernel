package main

import (
	"fmt"

	"seedloader/qjs"
)

// installPolyfills adds the few Web globals the shared host TS assumes but
// quickjs-ng does not provide. TextEncoder/TextDecoder are used
// at module-load time (e.g. core/domains.ts's DOMAIN constants), so this must run
// before any shared bundle is evaluated. UTF-8 only, which is all the host code
// needs. Guarded so a future quickjs-ng with native versions wins.
func installPolyfills(qc *qjs.Context) {
	if _, err := qc.Eval("polyfills.js", qjs.Code(polyfillsJS)); err != nil {
		panic(fmt.Sprintf("installPolyfills: %v", err))
	}
}

const polyfillsJS = `
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
        if (c === "=" || c === "\n" || c === "\r") continue;
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
})();
`
