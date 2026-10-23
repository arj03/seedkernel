// UTF-8 for engines with no TextEncoder or TextDecoder: every guest realm, which takes these
// by source (bundle-author.ts `guestOpFraming`), and the native host realm, whose polyfills
// are these (host/native-polyfills.ts). So both must reference nothing outside themselves,
// and this file imports nothing, which lets it load first in the host script.

/** UTF-8 as TextEncoder writes it: a surrogate pair is one four-byte sequence, a lone
 *  surrogate U+FFFD. */
export function utf8Encode(s: string): Uint8Array {
  // At most three bytes per UTF-16 code unit: a pair is two units and four bytes.
  const out = new Uint8Array(s.length * 3);
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdfff) {
      const lo = s.charCodeAt(i + 1);
      if (c < 0xdc00 && lo >= 0xdc00 && lo <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00); i++; }
      else c = 0xfffd;
    }
    if (c < 0x80) out[n++] = c;
    else if (c < 0x800) { out[n++] = 0xc0 | (c >> 6); out[n++] = 0x80 | (c & 63); }
    else if (c < 0x10000) { out[n++] = 0xe0 | (c >> 12); out[n++] = 0x80 | ((c >> 6) & 63); out[n++] = 0x80 | (c & 63); }
    else {
      out[n++] = 0xf0 | (c >> 18); out[n++] = 0x80 | ((c >> 12) & 63);
      out[n++] = 0x80 | ((c >> 6) & 63); out[n++] = 0x80 | (c & 63);
    }
  }
  return out.slice(0, n);
}

/** UTF-8 bytes as a string, the inverse of `utf8Encode` on what it writes. */
export function utf8Decode(b: Uint8Array): string {
  const units: number[] = [];
  let s = "";
  for (let i = 0; i < b.length;) {
    const c = b[i++];
    if (c < 0x80) units.push(c);
    else if (c < 0xe0) units.push(((c & 31) << 6) | (b[i++] & 63));
    else if (c < 0xf0) units.push(((c & 15) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63));
    else {
      const cp = (((c & 7) << 18) | ((b[i++] & 63) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63)) - 0x10000;
      units.push(0xd800 | (cp >> 10), 0xdc00 | (cp & 0x3ff));
    }
    // One String.fromCharCode per 4096 units, well under any engine's argument limit,
    // instead of one concatenation per character: a whole guest source decodes here.
    if (units.length >= 4096) {
      s += String.fromCharCode.apply(null, units);
      units.length = 0;
    }
  }
  return s + String.fromCharCode.apply(null, units);
}
