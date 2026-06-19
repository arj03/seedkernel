package main

import (
	"fmt"

	"seedloader/qjs"
)

// installPolyfills adds the few Web globals the shared host TS assumes but
// quickjs-ng does not provide. TextEncoder/TextDecoder are used
// at module-load time (e.g. net-link.ts's DOMAIN constant), so this must run
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
})();
`
