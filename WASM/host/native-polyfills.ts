// The few Web globals the shared host code assumes and quickjs-ng does not provide — the
// native HOST realm's, and only its: browser and Node have all of them, and a confined guest
// realm holds ECMAScript intrinsics on every target, these not among them (§12.3).
//
// FIRST in the native host bundle, so the globals exist before any module reaches for one at load
// time (services/domains.ts builds its DOMAIN constants with a `TextEncoder` at module scope).

/** The one `bridge` member this file uses (native-shim.ts declares the whole of it). */
declare const bridge: { log(line: string): void };

const web = globalThis as { TextEncoder?: unknown; TextDecoder?: unknown; console?: unknown };

if (web.TextEncoder === undefined) {
  web.TextEncoder = class TextEncoder {
    // Written straight into a typed array rather than pushed byte-by-byte into a plain one
    // and converted at the end. Three bytes per UTF-16 code unit is the ceiling — a
    // surrogate pair is two units and four bytes — plus one for the single case that beats
    // it: a lone high surrogate in the final position consumes one unit and still writes
    // four. That can happen once, because it ends the loop.
    encode(input: string): Uint8Array {
      const s = String(input);
      const out = new Uint8Array(s.length * 3 + 1);
      let n = 0;
      for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);
        if (c < 0x80) out[n++] = c;
        else if (c < 0x800) {
          out[n++] = 0xc0 | (c >> 6); out[n++] = 0x80 | (c & 0x3f);
        } else if (c >= 0xd800 && c <= 0xdbff) {
          const c2 = s.charCodeAt(++i);
          c = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
          out[n++] = 0xf0 | (c >> 18); out[n++] = 0x80 | ((c >> 12) & 0x3f);
          out[n++] = 0x80 | ((c >> 6) & 0x3f); out[n++] = 0x80 | (c & 0x3f);
        } else {
          out[n++] = 0xe0 | (c >> 12); out[n++] = 0x80 | ((c >> 6) & 0x3f);
          out[n++] = 0x80 | (c & 0x3f);
        }
      }
      return out.slice(0, n);
    }
  };
}

if (web.TextDecoder === undefined) {
  // Code units per String.fromCharCode call. This is the ONLY decoder the native target
  // has — it reads every manifest, every guest source and every fs listing — so the batch
  // is what keeps it from building those strings one concatenation per character. Well
  // under any engine argument limit, since a batch is spread as arguments.
  const CHUNK = 4096;
  web.TextDecoder = class TextDecoder {
    decode(buf?: ArrayBuffer | ArrayLike<number>): string {
      const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf ?? []);
      const units: number[] = [];
      let s = "";
      for (let i = 0; i < b.length; ) {
        let c = b[i++];
        if (c < 0x80) units.push(c);
        else if (c < 0xe0) units.push(((c & 0x1f) << 6) | (b[i++] & 0x3f));
        else if (c < 0xf0) units.push(((c & 0x0f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f));
        else {
          c = ((c & 0x07) << 18) | ((b[i++] & 0x3f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f);
          c -= 0x10000;
          units.push(0xd800 + (c >> 10), 0xdc00 + (c & 0x3ff));
        }
        if (units.length >= CHUNK) {
          s += String.fromCharCode.apply(null, units);
          units.length = 0;
        }
      }
      return units.length === 0 ? s : s + String.fromCharCode.apply(null, units);
    }
  };
}

// console — quickjs-ng defines none, and shared host code logs through one, not least from
// the handler that reports a wedged transport guest. Everything goes to STDERR through
// `bridge.log`, because stdout carries the app's raw response bytes for --op.
{
  const show = (a: unknown): string => {
    if (typeof a === "string") return a;
    // Message first: quickjs's `stack` is the frames ALONE, so printing it by itself drops
    // the part that says what went wrong.
    if (a instanceof Error) return a.stack ? String(a) + "\n" + a.stack : String(a);
    try {
      const j = JSON.stringify(a);
      if (j !== undefined) return j;
    } catch { /* cyclic, or a toJSON that throws — fall through to String */ }
    return String(a);
  };
  const sink = (...args: unknown[]): void => { bridge.log(args.map(show).join(" ")); };
  web.console = { log: sink, info: sink, debug: sink, warn: sink, error: sink, trace: sink };
}

export {};
